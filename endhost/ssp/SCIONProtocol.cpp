#include <arpa/inet.h>
#include <ifaddrs.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <net/if.h>
#include <sys/un.h>
#include <unistd.h>

#include "Extensions.h"
#include "Path.h"
#include "ProtocolConfigs.h"
#include "SCIONProtocol.h"
#include "Utils.h"

void timerCleanup(void *arg)
{
    SCIONProtocol *p = (SCIONProtocol *)arg;
    p->threadCleanup();
}

void * timerThread(void *arg)
{
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    SCIONProtocol *p = (SCIONProtocol *)arg;
    pthread_cleanup_push(timerCleanup, arg);
    while (p->isRunning()) {
        p->handleTimerEvent();
        usleep(SCION_TIMER_INTERVAL);
    }
    pthread_cleanup_pop(1);
    return NULL;
}

SCIONProtocol::SCIONProtocol(int sock, const char *sciond)
    : mSrcPort(0),
    mDstPort(0),
    mIsReceiver(false),
    mReadyToRead(false),
    mBlocking(true),
    mState(SCION_RUNNING),
    mNextSendByte(0),
    mProbeNum(0),
    mInvalid(0)
{
    mSocket = sock; // gets closed by SCIONSocket
    mDaemonSocket = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, sciond);
    if (connect(mDaemonSocket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "failed to connect to sciond at %s: %s\n", sciond, strerror(errno));
        exit(1);
    }

    memset(&mLocalAddr, 0, sizeof(mLocalAddr));
    // get IP from OS to use as default for mLocalAddr
    // can specify different IP with bind() later
    getDefaultIP();
    memset(&mDstAddr, 0, sizeof(mDstAddr));

    gettimeofday(&mLastProbeTime, NULL);

    pthread_mutex_init(&mDispatcherMutex, NULL);
    pthread_mutex_init(&mPathMutex, NULL);
    pthread_mutex_init(&mStateMutex, NULL);
    pthread_mutex_init(&mReadMutex, NULL);

    pthread_condattr_t ca;
    pthread_condattr_init(&ca);
    pthread_condattr_setclock(&ca, CLOCK_REALTIME);
    pthread_cond_init(&mReadCond, &ca);
    pthread_cond_init(&mPathCond, &ca);
}

SCIONProtocol::~SCIONProtocol()
{
    mState = SCION_CLOSED;
    pthread_mutex_destroy(&mReadMutex);
    pthread_cond_destroy(&mReadCond);
    pthread_mutex_destroy(&mStateMutex);
    pthread_mutex_destroy(&mPathMutex);
    pthread_cond_destroy(&mPathCond);
    close(mDaemonSocket);
}

void SCIONProtocol::getDefaultIP()
{
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) < 0) {
        fprintf(stderr, "failed to get OS IP addr: %s\n", strerror(errno));
        exit(1);
    }
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;
        if (ifa->ifa_flags & IFF_LOOPBACK)
            continue;
        // TODO(aznair): IPv6
        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *sa = (struct sockaddr_in *)(ifa->ifa_addr);
            mLocalAddr.host.addr_type = ADDR_IPV4_TYPE;
            memcpy(mLocalAddr.host.addr, &sa->sin_addr, ADDR_IPV4_LEN);
            break;
        } else if (ifa->ifa_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)(ifa->ifa_addr);
            mLocalAddr.host.addr_type = ADDR_IPV6_TYPE;
            memcpy(mLocalAddr.host.addr, &sa6->sin6_addr, ADDR_IPV6_LEN);
            break;
        }
    }
    freeifaddrs(ifaddr);
}

int SCIONProtocol::maxPayloadSize(double timeout)
{
    int min = INT_MAX;
    pthread_mutex_lock(&mPathMutex);
    while (mPaths.size() - mInvalid == 0) {
        if (timeout > 0.0) {
            if (timedWait(&mPathCond, &mPathMutex, timeout) == ETIMEDOUT) {
                pthread_mutex_unlock(&mPathMutex);
                DEBUG("%p: timeout getting max payload size (no paths)\n", this);
                return -ETIMEDOUT;
            }
        } else {
            pthread_cond_wait(&mPathCond, &mPathMutex);
        }
    }
    for (size_t i = 0; i < mPaths.size(); i++) {
        if (!mPaths[i])
            continue;
        int size = mPaths[i]->getPayloadLen(false);
        if (size < min)
            min = size;
    }
    pthread_mutex_unlock(&mPathMutex);
    return min;
}

void SCIONProtocol::queryLocalAddress()
{
    DEBUG("%s\n", __func__);
    uint8_t buf[32];

    buf[0] = 1;
    send_dp_header(mDaemonSocket, NULL, 1);
    send_all(mDaemonSocket, buf, 1);
    recv_all(mDaemonSocket, buf, DP_HEADER_LEN);
    int len = 0;
    parse_dp_header(buf, NULL, &len);
    if (len == -1) {
        fprintf(stderr, "out of sync with sciond\n");
        exit(1);
    }
    recv_all(mDaemonSocket, buf, len);
    mLocalAddr.isd_as = ntohl(*(uint32_t *)buf);
}

int SCIONProtocol::setRemoteAddress(SCIONAddr addr, double timeout)
{
    DEBUG("%p: setRemoteAddress: (%d-%d)\n", this, ISD(addr.isd_as), AS(addr.isd_as));
    if (addr.isd_as == mDstAddr.isd_as) {
        DEBUG("%p: dst addr already set: (%d-%d)\n", this, ISD(mDstAddr.isd_as), AS(mDstAddr.isd_as));
        return -EPERM;
    }

    mDstAddr = addr;

    double waitTime = timeout;
    struct timeval start, end;

    pthread_mutex_lock(&mPathMutex);
    for (size_t i = 0; i < mPaths.size(); i++) {
        Path *p = mPaths[i];
        if (p)
            delete p;
    }
    mPaths.clear();
    mInvalid = 0;

    while (mPaths.size() - mInvalid == 0) {
        DEBUG("%p: trying to connect but no paths available\n", this);
        gettimeofday(&start, NULL);
        getPaths(waitTime);
        gettimeofday(&end, NULL);
        long delta = elapsedTime(&start, &end);
        waitTime -= delta / 1000000.0;
        if (timeout > 0.0 && waitTime < 0) {
            pthread_mutex_unlock(&mPathMutex);
            return -ETIMEDOUT;
        }
    }
    pthread_mutex_unlock(&mPathMutex);
    return 0;
}

void SCIONProtocol::getPaths(double timeout)
{
    int buflen = (MAX_PATH_LEN + 15) * MAX_TOTAL_PATHS;
    int recvlen;
    uint8_t buf[buflen];

    memset(buf, 0, buflen);

    // Get local address first
    if (mLocalAddr.isd_as == 0) {
        queryLocalAddress();
    }

    prunePaths();
    int numPaths = mPaths.size() - mInvalid;

    if (timeout > 0.0) {
        struct timeval t;
        t.tv_sec = (size_t)floor(timeout);
        t.tv_usec = (size_t)((timeout - floor(timeout)) * 1000000);
        setsockopt(mDaemonSocket, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof(t));
    }

    // Now get paths for remote address(es)
    std::vector<Path *> candidates;
    memset(buf, 0, buflen);
    *(uint32_t *)(buf + 1) = htonl(mDstAddr.isd_as);
    send_dp_header(mDaemonSocket, NULL, 5);
    send_all(mDaemonSocket, buf, 5);

    memset(buf, 0, buflen);
    recvlen = recv_all(mDaemonSocket, buf, DP_HEADER_LEN);
    if (recvlen < 0) {
        DEBUG("error while receiving header from sciond: %s\n", strerror(errno));
        return;
    }
    parse_dp_header(buf, NULL, &recvlen);
    if (recvlen == -1) {
        fprintf(stderr, "out of sync with sciond\n");
        exit(1);
    }
    int reallen = recvlen > buflen ? buflen : recvlen;
    reallen = recv_all(mDaemonSocket, buf, reallen);
    if (reallen > 0) {
        DEBUG("%d byte response from daemon\n", reallen);
        int offset = 0;
        while (offset < reallen &&
                numPaths + candidates.size() < MAX_TOTAL_PATHS) {
            uint8_t *ptr = buf + offset;
            int pathLen = checkPath(ptr, reallen - offset, candidates);
            if (pathLen < 0)
                break;
            offset += pathLen;
        }
    }
    insertPaths(candidates);
    DEBUG("total %lu paths\n", mPaths.size() - mInvalid);

    // If sciond sent excess data, consume it to sync state
    if (reallen < recvlen) {
        int remaining = recvlen - reallen;
        while (remaining > 0) {
            int read = recv(mDaemonSocket, buf, buflen, 0);
            if (read < 0)
                break;
            remaining -= read;
        }
    }

    pthread_cond_broadcast(&mPathCond);
}

void SCIONProtocol::prunePaths()
{
    for (size_t i = 0; i < mPaths.size(); i++) {
        Path *p = mPaths[i];
        if (p && (!p->isValid() || !mPolicy.validate(p))) {
            DEBUG("path %lu not valid\n", i);
            mPaths[i] = NULL;
            delete p;
            mInvalid++;
        }
    }
}

void SCIONProtocol::insertPaths(std::vector<Path *> &candidates)
{
    if (candidates.empty())
        return;

    for (size_t i = 0; i < mPaths.size(); i++) {
        if (mPaths[i])
            continue;
        Path *p = candidates.front();
        candidates.erase(candidates.begin());
        mPaths[i] = p;
        p->setIndex(i);
        mInvalid--;
        if (candidates.empty())
            break;
    }
    for (size_t i = 0; i < candidates.size(); i++) {
        Path *p = candidates[i];
        int index = mPaths.size();
        mPaths.push_back(p);
        p->setIndex(index);
    }
}

int SCIONProtocol::checkPath(uint8_t *ptr, int len, std::vector<Path *> &candidates)
{
    bool add = true;
    int pathLen = *ptr * 8;
    if (pathLen + 1 > len)
        return -1;
    uint8_t addr_type = *(ptr + 1 + pathLen);
    int addr_len = get_addr_len(addr_type);
    // TODO: IPv6 (once sciond supports it)
    int interfaceOffset = 1 + pathLen + 1 + addr_len + 2 + 2;
    int interfaceCount = *(ptr + interfaceOffset);
    if (interfaceOffset + 1 + interfaceCount * IF_TOTAL_LEN > len)
        return -1;
    for (size_t j = 0; j < mPaths.size(); j++) {
        if (mPaths[j] &&
                mPaths[j]->isSamePath(ptr + 1, pathLen)) {
            add = false;
            break;
        }
    }
    for (size_t j = 0; j < candidates.size(); j++) {
        if (candidates[j]->usesSameInterfaces(ptr + interfaceOffset + 1, interfaceCount)) {
            add = false;
            break;
        }
    }
    if (add) {
        Path *p = createPath(mDstAddr, ptr, 0);
        if (mPolicy.validate(p))
            candidates.push_back(p);
        else
            delete p;
    }
    return interfaceOffset + 1 + interfaceCount * IF_TOTAL_LEN;
}

int SCIONProtocol::insertOnePath(Path *p)
{
    for (size_t i = 0; i < mPaths.size(); i++) {
        if (mPaths[i])
            continue;
        mPaths[i] = p;
        p->setIndex(i);
        mInvalid--;
        return i;
    }
    int index = mPaths.size();
    mPaths.push_back(p);
    p->setIndex(index);
    return index;
}

Path * SCIONProtocol::createPath(SCIONAddr &dstAddr, uint8_t *rawPath, int pathLen)
{
    return NULL;
}

int SCIONProtocol::bind(SCIONAddr addr, int sock)
{
    DEBUG("%p: bind to (%d-%d):%s\n",
            this, ISD(addr.isd_as), AS(addr.isd_as),
            addr_to_str(addr.host.addr, addr.host.addr_type, NULL));

    mSrcPort = addr.host.port;
    if (mLocalAddr.isd_as == 0)
        queryLocalAddress();
    if (addr.isd_as == 0) /* bind to any address */
        return 0;
    mLocalAddr.host.addr_type = addr.host.addr_type;
    memcpy(mLocalAddr.host.addr, addr.host.addr, get_addr_len(addr.host.addr_type));
    return 0;
}

int SCIONProtocol::connect(SCIONAddr addr, double timeout)
{
    return 0;
}

int SCIONProtocol::listen(int sock)
{
    return 0;
}

int SCIONProtocol::send(uint8_t *buf, size_t len, SCIONAddr *dstAddr, double timeout)
{
    return 0;
}

int SCIONProtocol::recv(uint8_t *buf, size_t len, SCIONAddr *srcAddr, double timeout)
{
    return 0;
}

int SCIONProtocol::handlePacket(SCIONPacket *packet, uint8_t *buf)
{
    return 0;
}

void SCIONProtocol::handleTimerEvent()
{
}

void SCIONProtocol::handlePathError(SCIONPacket *packet)
{
    pthread_mutex_lock(&mPathMutex);
    for (size_t i = 0; i < mPaths.size(); i++) {
        if (mPaths[i] && mPaths[i]->isSamePath(packet->header.path, packet->header.pathLen)) {
            DEBUG("path %lu is invalid\n", i);
            delete mPaths[i];
            mPaths[i] = NULL;
            mInvalid++;
            break;
        }
    }
    getPaths();
    pthread_mutex_unlock(&mPathMutex);
}

bool SCIONProtocol::isReceiver()
{
    return mIsReceiver;
}

bool SCIONProtocol::isRunning()
{
    return mState != SCION_CLOSED;
}

void SCIONProtocol::setReceiver(bool receiver)
{
    mIsReceiver = receiver;
}

void SCIONProtocol::setBlocking(bool blocking)
{
    mBlocking = blocking;
}

bool SCIONProtocol::isBlocking()
{
    return mBlocking;
}

bool SCIONProtocol::claimPacket(SCIONPacket *packet, uint8_t *buf)
{
    return false;
}

void SCIONProtocol::start(SCIONPacket *packet, uint8_t *buf, int sock)
{
}

void SCIONProtocol::getStats(SCIONStats *stats)
{
}

bool SCIONProtocol::readyToRead()
{
    return false;
}

bool SCIONProtocol::readyToWrite()
{
    return false;
}

int SCIONProtocol::registerSelect(Notification *n, int mode)
{
    return 0;
}

void SCIONProtocol::deregisterSelect(int index)
{
}

int SCIONProtocol::registerDispatcher(uint64_t flowID, uint16_t port, int sock)
{
    return 0;
}

int SCIONProtocol::setISDWhitelist(void *data, size_t len)
{
    // Disallow changing policy if connection is already active
    if (mNextSendByte != 1)
        return -EPERM;
    if (len % 2 != 0) {
        DEBUG("List of ISDs should have an even total length\n");
        return -EINVAL;
    }

    if (mLocalAddr.isd_as == 0) {
        queryLocalAddress();
    }

    std::vector<uint16_t> isds;
    bool foundSelf = false;
    bool foundDst = false;
    for (size_t i = 0; i < len / 2; i ++) {
        uint16_t isd = *((uint16_t *)data + i);
        if (isd == ISD(mLocalAddr.isd_as))
            foundSelf = true;
        if (isd == ISD(mDstAddr.isd_as))
            foundDst = true;
        isds.push_back(isd);
    }

    if (len > 0) {
        if (!foundSelf) {
            DEBUG("Own ISD not whitelisted\n");
            return -EINVAL;
        }
        if (!foundDst) {
            DEBUG("Destination ISD not whitelisted\n");
            return -EINVAL;
        }
    }

    mPolicy.setISDWhitelist(isds);
    pthread_mutex_lock(&mPathMutex);
    getPaths();
    pthread_mutex_unlock(&mPathMutex);
    return 0;
}

int SCIONProtocol::shutdown(bool force)
{
    return 0;
}

uint32_t SCIONProtocol::getLocalIA()
{
    if (mLocalAddr.isd_as == 0)
        queryLocalAddress();
    return mLocalAddr.isd_as;
}

void SCIONProtocol::threadCleanup()
{
    pthread_mutex_unlock(&mReadMutex);
    pthread_mutex_unlock(&mStateMutex);
    pthread_mutex_unlock(&mPathMutex);
}

int SCIONProtocol::getPort()
{
    return mSrcPort;
}

int SCIONProtocol::sendRawPacket(uint8_t *buf, int len, HostAddr *firstHop)
{
    pthread_mutex_lock(&mDispatcherMutex);
    send_dp_header(mSendSocket, firstHop, len);
    int sent = send_all(mSendSocket, buf, len);
    pthread_mutex_unlock(&mDispatcherMutex);
    return sent;
}

void SCIONProtocol::didSend(SCIONPacket *packet)
{
}

// SSP

SSPProtocol::SSPProtocol(int sock, const char *sciond)
    : SCIONProtocol(sock, sciond),
    mInitialized(false),
    mInitAckCount(0),
    mFlowID(0),
    mLowestPending(0),
    mHighestReceived(0),
    mAckVectorOffset(0),
    mTotalReceived(0),
    mNextPacket(0),
    mSelectCount(0),
    mRunning(true),
    mFinAcked(false),
    mFinAttempts(0),
    mInitAcked(false),
    mResendInit(true),
    mHighestAcked(0),
    mTotalSize(0)
{
    mProtocolID = L4_SSP;
    mProbeInterval = SSP_PROBE_INTERVAL;
    mReadyPackets = new OrderedList<SSPPacket *>(NULL, destroySSPPacket);

    getWindowSize();

    pthread_mutex_init(&mSelectMutex, NULL);

    mConnectionManager = new SSPConnectionManager(mSocket, sciond, this);
    mPathManager = mConnectionManager;
    pthread_create(&mTimerThread, NULL, timerThread, this);
}

SSPProtocol::~SSPProtocol()
{
    mState = SCION_CLOSED;
    pthread_cancel(mTimerThread);
    pthread_join(mTimerThread, NULL);
    if (mConnectionManager) {
        delete mConnectionManager;
        mConnectionManager = NULL;
    }
    mReadyPackets->clean();
    delete mReadyPackets;
    while (!mOOPackets.empty()) {
        SSPPacket *sp = mOOPackets.top();
        mOOPackets.pop();
        destroySSPPacket(sp);
    }
    pthread_mutex_destroy(&mSelectMutex);
}

int SSPProtocol::connect(SCIONAddr addr, double timeout)
{
    if (mNextSendByte != 0) {
        DEBUG("connection already established\n");
        return -1;
    }

    int ret = mConnectionManager->setRemoteAddress(addr, timeout);
    if (ret < 0) {
        DEBUG("setRemoteAddress failed: %d\n", ret);
        return ret;
    }
    mDstAddr = addr;
    mDstPort = addr.host.port;

    uint8_t buf = 0;
    SCIONPacket *packet = createPacket(&buf, 1);
    SSPPacket *sp = (SSPPacket *)packet->payload;
    sp->header.flags |= SSP_CON;
    mConnectionManager->queuePacket(packet);
    return 0;
}

int SSPProtocol::listen(int sock)
{
    SCIONAddr *addr = mConnectionManager->localAddress();
    if (addr->isd_as == 0) {
        DEBUG("socket not bound yet\n");
        return -1;
    }

    mSrcPort = registerDispatcher(0, 0, sock);
    return 0;
}

int SSPProtocol::send(uint8_t *buf, size_t len, SCIONAddr *dstAddr, double timeout)
{
    uint8_t *ptr = buf;
    size_t total_len = len;
    size_t room = mLocalSendWindow - mConnectionManager->totalQueuedSize();
    int packetMax = mConnectionManager->maxPayloadSize(timeout);

    if (packetMax < 0)
        return packetMax;

    if (!mBlocking && room < len) {
        DEBUG("non-blocking socket not ready to send\n");
        return -EWOULDBLOCK;
    }

    while (len > 0) {
        size_t packetLen = (size_t)packetMax > len ? len : packetMax;
        len -= packetLen;
        SCIONPacket *packet = createPacket(ptr, packetLen);
        if (mConnectionManager->waitForSendBuffer(packetLen, mLocalSendWindow, timeout) == -ETIMEDOUT) {
            DEBUG("timed out in send\n");
            return -ETIMEDOUT;
        }
        mConnectionManager->queuePacket(packet);
        ptr += packetLen;
    }
    return total_len;
}

int SSPProtocol::recv(uint8_t *buf, size_t len, SCIONAddr *srcAddr, double timeout)
{
    int total = 0;
    uint8_t *ptr = buf;
    bool missing = false;

    pthread_mutex_lock(&mReadMutex);
    while (!mReadyToRead) {
        DEBUG("%p: no data to read yet\n", this);
        if (!mBlocking) {
            pthread_mutex_unlock(&mReadMutex);
            DEBUG("non-blocking socket not ready to recv\n");
            return -EWOULDBLOCK;
        }
        if (timeout > 0.0) {
            if (timedWait(&mReadCond, &mReadMutex, timeout) == ETIMEDOUT) {
                pthread_mutex_unlock(&mReadMutex);
                DEBUG("%p: timeout in recv\n", this);
                return -ETIMEDOUT;
            }
        } else {
            pthread_cond_wait(&mReadCond, &mReadMutex);
        }
    }
    pthread_mutex_lock(&mStateMutex);
    if (mState == SCION_CLOSED || mState == SCION_FIN_READ) {
        pthread_mutex_unlock(&mStateMutex);
        pthread_mutex_unlock(&mReadMutex);
        DEBUG("%p: connection has already terminated (%d)\n", this, mState);
        return 0;
    }
    pthread_mutex_unlock(&mStateMutex);

    DEBUG("%p: start recv\n", this);
    while (!mReadyPackets->empty()) {
        if (total >= (int)len) {
            DEBUG("filled user buffer\n");
            break;
        }
        SSPPacket *sp = mReadyPackets->front();
        if (sp->getOffset() != mNextPacket) {
            DEBUG("missing packet %lu\n", mNextPacket);
            missing = true;
            break;
        }
        size_t currentPacket = sp->len - sp->dataOffset;
        size_t toRead = len - total > currentPacket ? currentPacket : len - total;
        DEBUG("reading %lu bytes\n", toRead);
        if (sp->header.flags & SSP_FIN) {
            DEBUG("%p: recv'd FIN packet\n", this);
            pthread_mutex_lock(&mStateMutex);
            mState = SCION_FIN_READ;
            pthread_mutex_unlock(&mStateMutex);
        } else {
            memcpy(ptr, sp->data.get() + sp->dataOffset, toRead);
            ptr += toRead;
            total += toRead;
            sp->dataOffset += toRead;
        }
        if (sp->dataOffset == sp->len) {
            DEBUG("%p: done with packet %lu\n", this, sp->getOffset());
            mReadyPackets->pop();
            mNextPacket += sp->len;
            mTotalReceived -= sizeof(SSPPacket) + sp->len;
            DEBUG("%u bytes in receive buffer\n", mTotalReceived);
            destroySSPPacket(sp);
        }
    }
    if (mReadyPackets->empty() || missing) {
        DEBUG("no more data ready\n");
        pthread_mutex_lock(&mStateMutex);
        if (mState != SCION_CLOSED && mState != SCION_FIN_READ)
            mReadyToRead = false;
        pthread_mutex_unlock(&mStateMutex);
    }
    pthread_mutex_unlock(&mReadMutex);
    if (!total)
        DEBUG("%p: connection has terminated\n", this);
    DEBUG("%p: recv'd total %d bytes\n", this, total);
    return total;
}

bool SSPProtocol::claimPacket(SCIONPacket *packet, uint8_t *buf)
{
    uint64_t flowID = be64toh(*(uint64_t *)buf) & ~1;
    DEBUG("mFlowID = %lu, incoming flowID = %lu\n", mFlowID, flowID);
    return flowID == mFlowID;
}

void SSPProtocol::start(SCIONPacket *packet, uint8_t *buf, int sock)
{
    if (buf) {
        mIsReceiver = true;
        mFlowID = be64toh(*(uint64_t *)buf) & ~1;
    } else {
        mIsReceiver = false;
        mFlowID = createRandom(64) & ~1;
    }
    DEBUG("%lu created\n", mFlowID);

    mSrcPort = registerDispatcher(0, 0, sock);
    DEBUG("start protocol for flow %lu\n", mFlowID);
    if (packet && buf)
        handlePacket(packet, buf);
}

void SSPProtocol::getWindowSize()
{
    // Eventually determine based on system resources
    mLocalReceiveWindow = SSP_DEFAULT_SEND_WINDOW_SIZE;
    mLocalSendWindow = SSP_DEFAULT_RECV_WINDOW_SIZE;
}

int SSPProtocol::getDeadlineFromProfile(DataProfile profile)
{
    return 50000;
}

int SSPProtocol::handlePacket(SCIONPacket *packet, uint8_t *buf)
{
    DEBUG("incoming SSP packet\n");

    uint8_t *ptr = buf;
    SCIONCommonHeader *sch = &packet->header.commonHeader;
    if (mDstAddr.isd_as == 0) {
        mDstAddr.isd_as = ntohl(*(uint32_t *)(packet->header.srcAddr));
        mDstAddr.host.addr_type = SRC_TYPE(sch);
        memcpy(mDstAddr.host.addr, packet->header.srcAddr + ISD_AS_LEN, get_addr_len(mDstAddr.host.addr_type));
    }

    // Build SSP incoming packet
    SSPPacket *sp = new SSPPacket();
    buildSSPHeader(&(sp->header), ptr);
    int payloadLen = sch->total_len - sch->header_len - sp->header.headerLen;
    SCIONExtension *ext = packet->header.extensions;
    while (ext != NULL) {
        payloadLen -= (ext->headerLen + 1) * 8;
        ext = ext->nextExt;
    }
    DEBUG("payload len = %d\n", payloadLen);
    sp->len = payloadLen;
    ptr += sizeof(SSPHeader);

    if (sp->header.flags & SSP_WINDOW) {
        mRemoteWindow = ntohl(*(uint32_t *)ptr);
        mConnectionManager->setRemoteWindow(mRemoteWindow);
        DEBUG("remote window = %d\n", mRemoteWindow);
        ptr += 4;
    }

    if (sp->header.flags & SSP_NEW_PATH) {
        sp->interfaceCount = *ptr++;
        DEBUG("%lu interfaces in new path\n", sp->interfaceCount);
        int interfaceLen = IF_TOTAL_LEN * sp->interfaceCount;
        sp->interfaces = (uint8_t *)malloc(interfaceLen);
        memcpy(sp->interfaces, ptr, interfaceLen);
        ptr += interfaceLen;
    }

    packet->payload = sp;
    mConnectionManager->handlePacket(packet, mIsReceiver);

    if (sp->header.flags & SSP_ACK) {
        DEBUG("incoming packet is ACK\n");
        buildSSPAck(&(sp->ack), ptr);
        mConnectionManager->handleAck(packet, mInitAckCount, mIsReceiver);
    }

    ext = findProbeExtension(&packet->header);
    if (ext != NULL) {
        uint32_t probeNum = getProbeNum(ext);
        if (isProbeAck(ext)) {
            if (probeNum == mProbeNum)
                mConnectionManager->handleProbeAck(packet);
        } else {
            handleProbe(packet);
        }
    }

    if (payloadLen > 0 ||
            ((sp->header.flags & SSP_FIN) && !(sp->header.flags & SSP_ACK))) {
        if (payloadLen > 0) {
            sp->data = std::shared_ptr<uint8_t>((uint8_t *)malloc(payloadLen), free);
            memcpy(sp->data.get(), ptr, payloadLen);
            sp->len = payloadLen;
        }
        handleData(sp, packet->pathIndex);
    } else {
        destroySSPPacket(sp);
    }

    destroySCIONPacket(packet);
    return 0;
}

void SSPProtocol::handleProbe(SCIONPacket *packet)
{
    DEBUG("incoming probe\n");
    SCIONExtension *ext = findProbeExtension(&packet->header);
    uint32_t probeNum = getProbeNum(ext);
    SCIONAddr *localAddr = mConnectionManager->localAddress();
    SCIONPacket p;
    memset(&p, 0, sizeof(p));
    pack_cmn_hdr((uint8_t *)&p.header.commonHeader,
            localAddr->host.addr_type, mDstAddr.host.addr_type, L4_SSP, 0, 0, 0);
    addProbeExtension(&p.header, probeNum, 1);
    p.pathIndex = packet->pathIndex;
    SSPPacket sp;
    p.payload = &sp;
    if (mIsReceiver)
        sp.setFlowID(mFlowID);
    else
        sp.setFlowID(mFlowID | 1);
    sp.header.headerLen = sizeof(sp.header);
    mConnectionManager->sendAck(&p);
}

SSPPacket * SSPProtocol::checkOutOfOrderQueue(SSPPacket *sp)
{
    uint64_t start = sp->getOffset();
    uint64_t end = start + sp->len;
    bool pushed = false;
    SSPPacket *last = sp;
    if (mOOPackets.empty()) {
        mReadyPackets->push(sp);
        mLowestPending = end;
        pushed = true;
    } else {
        while (!mOOPackets.empty()) {
            DEBUG("check out-of-order queue\n");
            last = (SSPPacket *)mOOPackets.top();
            if (last->getOffset() < end)
                break;
            if (!pushed) {
                mReadyPackets->push(sp);
                mLowestPending = end;
                pushed = true;
            }
            start = last->getOffset();
            end = start + last->len;
            DEBUG("packet: %lu ~ %lu\n", start, end);
            if (start <= mLowestPending && end > mLowestPending) {
                mOOPackets.pop();
                mReadyPackets->push(last);
                mLowestPending = end;
            } else {
                break;
            }
        }
    }
    return pushed ? last : NULL;
}

void SSPProtocol::signalSelect()
{
    DEBUG("signalSelect\n");
    pthread_mutex_lock(&mSelectMutex);
    std::map<int, Notification>::iterator i;
    for (i = mSelectRead.begin(); i != mSelectRead.end(); i++) {
        Notification &n = i->second;
        pthread_mutex_lock(n.mutex);
        pthread_cond_signal(n.cond);
        pthread_mutex_unlock(n.mutex);
        DEBUG("signalled select cond %d\n", i->first);
    }
    for (i = mSelectWrite.begin(); i != mSelectWrite.end(); i++) {
        Notification &n = i->second;
        pthread_mutex_lock(n.mutex);
        pthread_cond_signal(n.cond);
        pthread_mutex_unlock(n.mutex);
        DEBUG("signalled select cond %d\n", i->first);
    }
    pthread_mutex_unlock(&mSelectMutex);
}

void SSPProtocol::handleInOrder(SSPPacket *sp, int pathIndex)
{
    DEBUG("in-order packet: %lu\n", sp->getOffset());

    uint64_t start = sp->getOffset();
    uint64_t end = start + sp->len;
    int packetSize = end - start + sizeof(SSPPacket);

    pthread_mutex_lock(&mReadMutex);

    if (!(sp->header.flags & SSP_FIN) &&
            packetSize + mTotalReceived > mLocalReceiveWindow) {
        DEBUG("in-order packet %lu: Receive window too full: %u/%u\n",
                sp->getOffset(), mTotalReceived, mLocalReceiveWindow);
        sp->setOffset(mHighestReceived);
        sendAck(sp, pathIndex);
        sp->data = NULL;
        destroySSPPacket(sp);
        pthread_mutex_unlock(&mReadMutex);
        return;
    }

    if (end - 1 > mHighestReceived)
        mHighestReceived = end - 1;

    SSPPacket *last = checkOutOfOrderQueue(sp);
    if (last) {
        DEBUG("lowest pending now %lu\n", mLowestPending);
        mTotalReceived += packetSize;
        DEBUG("receive window now %u/%u\n", mTotalReceived, mLocalReceiveWindow);
        sendAck(sp, pathIndex);
        mReadyToRead = true;
        if (last->header.flags & SSP_FIN) {
            DEBUG("%p: Read up to FIN flag, connection done\n", this);
            pthread_mutex_lock(&mStateMutex);
            mState = SCION_FIN_RCVD;
            pthread_mutex_unlock(&mStateMutex);
        }
    } else {
        DEBUG("packet was resent on smaller path(s), discard original\n");
    }
    pthread_mutex_unlock(&mReadMutex);
    pthread_cond_signal(&mReadCond);
    signalSelect();
}

void SSPProtocol::handleOutOfOrder(SSPPacket *sp, int pathIndex)
{
    DEBUG("out-of-order packet %lu (%lu)\n", sp->getOffset(), mLowestPending);

    uint64_t start = sp->getOffset();
    uint64_t end = start + sp->len;
    int maxPayload = mConnectionManager->maxPayloadSize();
    int packetSize = end - start + sizeof(SSPPacket);

    pthread_mutex_lock(&mReadMutex);

    if (!(sp->header.flags & SSP_FIN) &&
            packetSize + mTotalReceived > mLocalReceiveWindow - maxPayload) {
        DEBUG("out-of-order packet %lu(%lu): Receive window too full: %d/%u\n",
                sp->getOffset(), mLowestPending,
                mTotalReceived, mLocalReceiveWindow);
        sp->setOffset(mHighestReceived);
        sendAck(sp, pathIndex);
        sp->data = NULL;
        destroySSPPacket(sp);
        pthread_mutex_unlock(&mReadMutex);
        return;
    }

    if (end - 1 > mHighestReceived)
        mHighestReceived = end - 1;

    bool found = mOOSet.find(sp->getOffset()) != mOOSet.end();
    if (found) {
        DEBUG("duplicate packet: discard\n");
        pthread_mutex_unlock(&mReadMutex);
        sendAck(sp, pathIndex);
        destroySSPPacket(sp);
    } else {
        mOOPackets.push(sp);
        mOOSet.insert(sp->getOffset());
        DEBUG("added to out-of-order queue: top is %lu\n", mOOPackets.top()->getOffset());
        mTotalReceived += packetSize;
        DEBUG("receive window now %u/%u\n", mTotalReceived, mLocalReceiveWindow);
        pthread_mutex_unlock(&mReadMutex);
        sendAck(sp, pathIndex);
    }
}

void SSPProtocol::handleData(SSPPacket *sp, int pathIndex)
{
    uint64_t start = sp->getOffset();
    uint64_t end = start + sp->len;
    DEBUG("Incoming SSP packet %lu ~ %lu\n", start, end);

    if (mIsReceiver && start == 0) {
        DEBUG("Connect packet received\n");
        mLowestPending = mLowestPending > end ? mLowestPending : end;
        mNextPacket = mNextPacket > end ? mNextPacket : end;
        sendAck(sp, pathIndex);
        destroySSPPacket(sp);
        return;
    }

    if (end <= mLowestPending && !(sp->header.flags & SSP_FIN)) {
        DEBUG("Obsolete packet\n");
        sendAck(sp, pathIndex);
        destroySSPPacket(sp);
        return;
    }

    if (sp->header.flags & SSP_FIN)
        DEBUG("%p: handleData for FIN packet %lu (%lu)\n", this, start, mLowestPending);

    struct timeval now;
    gettimeofday(&now, NULL);

    if (start == mLowestPending) {
        handleInOrder(sp, pathIndex);
    } else {
        handleOutOfOrder(sp, pathIndex);
    }
}

void SSPProtocol::sendAck(SSPPacket *inPacket, int pathIndex)
{
    uint64_t packetNum = inPacket->getOffset();
    DEBUG("%lu: send ack for %lu (path %d)\n", mFlowID, packetNum, pathIndex);

    if (inPacket->header.flags & SSP_FIN)
        DEBUG("%lu: send ack for FIN packet %lu\n", mFlowID, packetNum);

    SCIONAddr *localAddr = mConnectionManager->localAddress();
    SCIONPacket packet;
    memset(&packet, 0, sizeof(SCIONPacket));
    pack_cmn_hdr((uint8_t *)&packet.header.commonHeader,
            localAddr->host.addr_type, mDstAddr.host.addr_type, L4_SSP, 0, 0, 0);
    packet.pathIndex = pathIndex;

    SSPPacket sp;
    packet.payload = &sp;
    // basic header stuff
    SSPHeader &sh = sp.header;
    sh.flags |= SSP_ACK;
    if (inPacket->header.flags & SSP_FIN)
        sh.flags |= SSP_FIN;
    sh.headerLen = sizeof(SSPHeader) + sizeof(SSPAck);
    if (!mInitialized) {
        sh.flags |= SSP_WINDOW;
        sh.headerLen += 4;
        sp.windowSize = htonl(mLocalReceiveWindow);
        mRemoteWindow = inPacket->windowSize;
        mInitialized = true;
    }
    if (mIsReceiver)
        sp.setFlowID(mFlowID);
    else
        sp.setFlowID(mFlowID | 1);
    sp.setMark(inPacket->getMark());

    // ack stuff
    sp.setL(mLowestPending);
    sp.setI(packetNum - mLowestPending);
    sp.setH(mHighestReceived - mLowestPending);
    DEBUG("outgoing ACK: L = %lu, I = %d, H = %d, O = %d, V = %u\n",
            sp.getL(), sp.getI(), sp.getH(), sp.getO(), sp.getV());

    mConnectionManager->sendAck(&packet);
}

SCIONPacket * SSPProtocol::createPacket(uint8_t *buf, size_t len)
{
    SCIONAddr *localAddr = mConnectionManager->localAddress();
    SCIONPacket *packet = (SCIONPacket *)malloc(sizeof(SCIONPacket));
    memset(packet, 0, sizeof(SCIONPacket));
    pack_cmn_hdr((uint8_t *)&packet->header.commonHeader,
            localAddr->host.addr_type, mDstAddr.host.addr_type, L4_SSP, 0, 0, 0);

    SSPPacket *sp = new SSPPacket();
    packet->payload = sp;
    sp->header.headerLen = sizeof(SSPHeader);
    // Server's LSb is 1, so client sets outgoing LSb to 1
    if (mIsReceiver)
        sp->setFlowID(mFlowID);
    else
        sp->setFlowID(mFlowID | 1);
    sp->setPort(mInitialized ? 0 : mDstPort);
    sp->setOffset(mNextSendByte);
    DEBUG("%s: created packet %lu at %p\n", __func__, sp->getOffset(), packet);
    if (!mInitialized) {
        DEBUG("include window size for initial packet\n");
        sp->header.flags |= SSP_WINDOW;
        sp->windowSize = htonl(mLocalReceiveWindow);
        sp->header.headerLen += 4;
        mInitialized = true;
    }
    if (len > 0) {
        sp->data = std::shared_ptr<uint8_t>((uint8_t *)malloc(len), free);
        memcpy(sp->data.get(), buf, len);
    }
    sp->len = len;
    mNextSendByte += len;

    return packet;
}

void SSPProtocol::handleTimerEvent()
{
    struct timeval current;
    gettimeofday(&current, NULL);
    mConnectionManager->handleTimeout();
    if (mDstAddr.isd_as != 0 && elapsedTime(&mLastProbeTime, &current) >= (int32_t)mProbeInterval) {
        mConnectionManager->sendProbes(++mProbeNum, mIsReceiver ? mFlowID : mFlowID | 1);
        mLastProbeTime = current;
    }
}

void SSPProtocol::getStats(SCIONStats *stats)
{
    if (mConnectionManager)
        mConnectionManager->getStats(stats);
}

bool SSPProtocol::readyToRead()
{
    bool ready = false;
    pthread_mutex_lock(&mReadMutex);
    ready = mReadyToRead;
    pthread_mutex_unlock(&mReadMutex);
    return ready;
}

bool SSPProtocol::readyToWrite()
{
    return !mConnectionManager->bufferFull(mLocalSendWindow);
}

int SSPProtocol::registerSelect(Notification *n, int mode)
{
    pthread_mutex_lock(&mSelectMutex);
    if (mode == SCION_SELECT_READ)
        mSelectRead[++mSelectCount] = *n;
    else
        mSelectWrite[++mSelectCount] = *n;
    pthread_mutex_unlock(&mSelectMutex);
    DEBUG("registered index %d for mode %d\n", mSelectCount, mode);
    return mSelectCount;
}

void SSPProtocol::deregisterSelect(int index)
{
    pthread_mutex_lock(&mSelectMutex);
    if (mSelectRead.find(index) != mSelectRead.end()) {
        DEBUG("erase index %d from read list\n", index);
        mSelectRead.erase(index);
    } else {
        DEBUG("erase index %d from write list\n", index);
        mSelectWrite.erase(index);
    }
    pthread_mutex_unlock(&mSelectMutex);
}

void SSPProtocol::notifySender()
{
    pthread_mutex_lock(&mSelectMutex);
    std::map<int, Notification>::iterator i;
    for (i = mSelectWrite.begin(); i != mSelectWrite.end(); i++) {
        Notification &n = i->second;
        pthread_mutex_lock(n.mutex);
        pthread_cond_signal(n.cond);
        pthread_mutex_unlock(n.mutex);
    }
    pthread_mutex_unlock(&mSelectMutex);
}

int SSPProtocol::shutdown(bool force)
{
    pthread_mutex_lock(&mStateMutex);
    DEBUG("%p: shutdown\n", this);
    if (mState == SCION_CLOSED) {
        pthread_mutex_unlock(&mStateMutex);
        return 0;
    }
    if (force ||
            mState == SCION_FIN_READ ||
            mState == SCION_FIN_RCVD ||
            (!mIsReceiver && mNextSendByte == 0)) {
        if (mState == SCION_RUNNING)
            mState = SCION_CLOSED;
        pthread_mutex_unlock(&mStateMutex);
        pthread_mutex_lock(&mReadMutex);
        mReadyToRead = true;
        pthread_cond_broadcast(&mReadCond);
        pthread_mutex_unlock(&mReadMutex);
        return 0;
    }
    mState = SCION_SHUTDOWN;
    pthread_mutex_unlock(&mStateMutex);

    SCIONPacket *packet = createPacket(NULL, 0);
    SSPPacket *sp = (SSPPacket *)(packet->payload);
    sp->header.flags |= SSP_FIN;
    mConnectionManager->queuePacket(packet);
    DEBUG("%lu: FIN packet (%lu) queued\n", mFlowID, sp->getOffset());
    return 0;
}

void SSPProtocol::notifyFinAck()
{
    pthread_mutex_lock(&mStateMutex);
    mState = SCION_CLOSED;
    pthread_mutex_unlock(&mStateMutex);
    pthread_mutex_lock(&mReadMutex);
    mReadyToRead = true;
    pthread_cond_broadcast(&mReadCond);
    pthread_mutex_unlock(&mReadMutex);
}

int SSPProtocol::registerDispatcher(uint64_t flowID, uint16_t port, int sock)
{
    SCIONAddr *localAddr = mConnectionManager->localAddress();
    if (localAddr->isd_as == 0)
        mConnectionManager->queryLocalAddress();
    DispatcherEntry de;
    memset(&de, 0, sizeof(de));
    de.flow_id = flowID > 0 ? flowID : mFlowID;
    if (mIsReceiver)
        de.flow_id = de.flow_id | 1;
    de.port = port > 0 ? port : htons(mSrcPort);
    de.isd_as = htonl(localAddr->isd_as);
    de.addr_type = localAddr->host.addr_type;
    memcpy(de.addr, localAddr->host.addr, MAX_HOST_ADDR_LEN);
    int ret = registerFlow(L4_SSP, &de, sock);
    if (mSrcPort > 0 && ret == 0)
        return mSrcPort;
    return ret;
}

void SSPProtocol::threadCleanup()
{
    pthread_mutex_unlock(&mSelectMutex);
    SCIONProtocol::threadCleanup();
}

// SUDP

SUDPProtocol::SUDPProtocol(int sock, const char *sciond)
    : SCIONProtocol(sock, sciond),
    mTotalReceived(0)
{
    mConnectionManager = new SUDPConnectionManager(mSocket, sciond);
    mPathManager = mConnectionManager;
    pthread_create(&mTimerThread, NULL, timerThread, this);
}

SUDPProtocol::~SUDPProtocol()
{
    mState = SCION_CLOSED;
    pthread_join(mTimerThread, NULL);
    delete mConnectionManager;
}

int SUDPProtocol::bind(SCIONAddr addr, int sock)
{
    int ret = SCIONProtocol::bind(addr, sock);
    if (ret < 0)
        return ret;
    mSrcPort = registerDispatcher(0, addr.host.port, sock);
    if (mSrcPort < 0)
        return mSrcPort;
    return 0;
}

int SUDPProtocol::send(uint8_t *buf, size_t len, SCIONAddr *dstAddr, double timeout)
{
    if (dstAddr && mDstAddr.isd_as != dstAddr->isd_as) {
        memcpy(&mDstAddr, dstAddr, sizeof(SCIONAddr));
        mDstPort = mDstAddr.host.port;
        mConnectionManager->setRemoteAddress(mDstAddr);
    }
    DEBUG("send %lu byte packet\n", len);
    SCIONAddr *localAddr = mConnectionManager->localAddress();
    SCIONPacket packet;
    memset(&packet, 0, sizeof(packet));
    pack_cmn_hdr((uint8_t *)&packet.header.commonHeader,
            localAddr->host.addr_type, mDstAddr.host.addr_type, L4_UDP, 0, 0, 0);
    SUDPPacket sp;
    memset(&sp, 0, sizeof(sp));
    packet.payload = &sp;
    SUDPHeader &sh = sp.header;
    sh.srcPort = htons(mSrcPort);
    sh.dstPort = htons(mDstAddr.host.port);
    sh.len = htons(sizeof(SUDPHeader) + len);
    sp.payload = malloc(len);
    sp.payloadLen = len;
    memcpy(sp.payload, buf, len);
    return mConnectionManager->sendPacket(&packet);
}

int SUDPProtocol::recv(uint8_t *buf, size_t len, SCIONAddr *srcAddr, double timeout)
{
    DEBUG("recv max %lu bytes\n", len);
    int size = 0;
    pthread_mutex_lock(&mReadMutex);
    while (mReceivedPackets.empty()) {
        if (!mBlocking) {
            pthread_mutex_unlock(&mReadMutex);
            return -1;
        }
        if (timeout > 0.0) {
            if (timedWait(&mReadCond, &mReadMutex, timeout) == ETIMEDOUT) {
                pthread_mutex_unlock(&mReadMutex);
                DEBUG("%p: timeout in recv\n", this);
                return -ETIMEDOUT;
            }
        } else {
            pthread_cond_wait(&mReadCond, &mReadMutex);
        }
    }
    SCIONPacket *packet = mReceivedPackets.front();
    SUDPPacket *sp = (SUDPPacket *)(packet->payload);
    DEBUG("queued packet with len %lu bytes\n", sp->payloadLen);
    if (sp->payloadLen > len) {
        DEBUG("user buffer too short to read\n");
        pthread_mutex_unlock(&mReadMutex);
        return -1;
    }
    mReceivedPackets.pop_front();
    memcpy(buf, sp->payload, sp->payloadLen);
    size = sp->payloadLen;
    mTotalReceived -= sp->payloadLen + sizeof(SUDPPacket);
    pthread_mutex_unlock(&mReadMutex);
    DEBUG("recvd total %d bytes\n", size);
    if (srcAddr) {
        srcAddr->isd_as = ntohl(*(uint32_t *)packet->header.srcAddr);
        srcAddr->host.addr_type = SRC_TYPE(&(packet->header.commonHeader));
        memcpy(srcAddr->host.addr, packet->header.srcAddr + ISD_AS_LEN, MAX_HOST_ADDR_LEN);
        srcAddr->host.port = sp->header.srcPort;
    }
    destroySUDPPacket(sp);
    destroySCIONPacket(packet);
    return size;
}

int SUDPProtocol::handlePacket(SCIONPacket *packet, uint8_t *buf)
{
    DEBUG("SUDP packet\n");
    SCIONCommonHeader &sch = packet->header.commonHeader;
    uint8_t *ptr = buf;
    // SUDP header
    packet->payload = malloc(sizeof(SUDPPacket));
    memset(packet->payload, 0, sizeof(SUDPPacket));
    SUDPPacket *sp = (SUDPPacket *)(packet->payload);
    sp->header.srcPort = ntohs(*(uint16_t *)ptr);
    ptr += 2;
    mDstPort = sp->header.srcPort;
    sp->header.dstPort = ntohs(*(uint16_t *)ptr);
    ptr += 2;
    sp->header.len = ntohs(*(uint16_t *)ptr);
    ptr += 2;
    sp->header.checksum = ntohs(*(uint16_t *)ptr);
    ptr += 2;
    sp->payloadLen = sch.total_len - sch.header_len - sizeof(SUDPHeader);
    SCIONExtension *ext = packet->header.extensions;
    while (ext != NULL) {
        sp->payloadLen -= (ext->headerLen + 1) * SCION_EXT_LINE;
        ext = ext->nextExt;
    }
    bool isProbe = findProbeExtension(&packet->header) != NULL;
    DEBUG("payload %lu bytes\n", sp->payloadLen);
    if (sp->payloadLen > 0) {
        sp->payload = malloc(sp->payloadLen);
        memcpy(sp->payload, ptr, sp->payloadLen);
    }
    mConnectionManager->handlePacket(packet);
    if (!isProbe && sp->payloadLen > 0) {
        DEBUG("data packet\n");
        int size = sp->payloadLen + sizeof(SUDPPacket);
        if (mTotalReceived + size > SUDP_RECV_BUFFER) {
            DEBUG("recv buffer full, discard new packet\n");
            destroySUDPPacket(sp);
        } else {
            DEBUG("signal recv\n");
            pthread_mutex_lock(&mReadMutex);
            mTotalReceived += size;
            mReceivedPackets.push_back(packet);
            pthread_mutex_unlock(&mReadMutex);
            pthread_cond_signal(&mReadCond);
        }
    } else if (isProbe) {
        sp->payload = NULL;
        destroySUDPPacket(sp);
        destroySCIONPacket(packet);
    }
    return 0;
}

void SUDPProtocol::handleTimerEvent()
{
    struct timeval t;
    gettimeofday(&t, NULL);
    if (elapsedTime(&mLastProbeTime, &t) >= SUDP_PROBE_INTERVAL) {
        mConnectionManager->sendProbes(++mProbeNum, mSrcPort, mDstPort);
        mLastProbeTime = t;
    }
}

bool SUDPProtocol::claimPacket(SCIONPacket *packet, uint8_t *buf)
{
    return false;
}

void SUDPProtocol::start(SCIONPacket *packet, uint8_t *buf, int sock)
{
}

int SUDPProtocol::registerDispatcher(uint64_t flowID, uint16_t port, int sock)
{
    SCIONAddr *addr = mConnectionManager->localAddress();

    DispatcherEntry e;
    e.flow_id = flowID;
    e.port = port > 0 ? htons(port) : htons(mSrcPort);
    e.addr_type = addr->host.addr_type;
    e.isd_as = htonl(addr->isd_as);
    memcpy(e.addr, addr->host.addr, MAX_HOST_ADDR_LEN);
    return registerFlow(L4_UDP, &e, sock);
}

void SUDPProtocol::getStats(SCIONStats *stats)
{
}
