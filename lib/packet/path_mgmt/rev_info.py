# Copyright 2015 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
:mod:`rev_info` --- Revocation info payload
============================================
"""
# External
import capnp  # noqa

# SCION
import proto.rev_info_capnp as P
from lib.packet.path_mgmt.base import PathMgmtPayloadBase
from lib.types import PathMgmtType as PMT


class RevocationInfo(PathMgmtPayloadBase):
    """
    Class containing revocation information, i.e., the revocation token.
    """
    NAME = "RevocationInfo"
    PAYLOAD_TYPE = PMT.REVOCATION
    P_CLS = P.RevInfo

    @classmethod
    def from_values(cls, if_id, epoch, nonce, siblings, prev_root, next_root):
        """
        Returns a RevocationInfo object with the specified values.

        :param int if_id: ID of the interface to be revoked
        :param int epoch: Time epoch for which interface is to be revoked
        :param bytes nonce: Nonce for the (if_id, epoch) leaf in the hashtree
        :param list[(bool, bytes)] siblings: Positions and hashes of siblings
        :param bytes prev_root: Hash of the tree root at time T-1
        :param bytes next_root: Hash of the tree root at time T+1
        """
        # Put the if_id, epoch and nonce of the leaf into the proof.
        p = cls.P_CLS.new_message(ifID=if_id, epoch=epoch, nonce=nonce)
        # Put the list of sibling hashes (along with l/r) into the proof.
        sibs = p.init('siblings', len(siblings))
        for i, sibling in enumerate(siblings):
            sibs[i].isLeft, sibs[i].hash = sibling
        # Put the roots of the hash trees at T-1 and T+1.
        p.prevRoot = prev_root
        p.nextRoot = next_root
        return cls(p)

    def __hash__(self):
        b = []
        b.append(self.p.ifID.to_bytes(8, 'big'))
        b.append(self.p.epoch.to_bytes(2, 'big'))
        b.append(self.p.nonce)
        for sib in self.p.siblings:
            b.append(sib.isLeft.to_bytes(1, 'big'))
            b.append(sib.hash)
        b.append(self.p.prevRoot)
        b.append(self.p.nextRoot)
        return hash(b"".join(b))
