# Copyright 2016 ETH Zurich
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
:mod:`lib_crypto_hash_tree_test` --- lib.crypto.hash_tree unit tests
======================================================================
"""
# Stdlib
from unittest.mock import patch

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.crypto.hash_tree import (
    ConnectedHashTree,
    HashTree,
)
from lib.defines import (
    HASHTREE_EPOCH_TIME,
    HASHTREE_EPOCH_TOLERANCE,
)
from test.testcommon import create_mock_full


class TestHashTreeCalcTreeDepth(object):
    """
    Unit test for lib.crypto.hash_tree.HashTree.calc_tree_depth
    """
    @patch("lib.crypto.hash_tree.HashTree._setup", autospec=True)
    def test_for_non2power(self, _):
        # Setup
        inst = HashTree("if_ids", "seed")
        # Call
        inst.calc_tree_depth(6)
        # Tests
        ntools.eq_(inst._depth, 3)

    @patch("lib.crypto.hash_tree.HashTree._setup", autospec=True)
    def test_for_2power(self, _):
        # Setup
        if_ids = [1, 2, 3, 4]
        seed = b"abc"
        inst = HashTree(if_ids, seed)
        # Call
        inst.calc_tree_depth(8)
        # Tests
        ntools.eq_(inst._depth, 3)


class TestHashTreeCreateTree(object):
    """
    Unit test for lib.crypto.hash_tree.HashTree.calc_tree_depth
    """
    @patch("lib.crypto.hash_tree.HashTree._setup", autospec=True)
    def test(self, _):
        # Setup
        if_ids = [1, 2, 3]
        hashes = [b"s10", b"10s10", b"s20", b"20s20", b"s30", b"30s30",
                  b"0", b"30s300", b"10s1020s20", b"10s1020s2030s300"]
        hash_new = create_mock_full({"digest()...": hashes})
        hash_func = create_mock_full({"new()": hash_new})
        inst = HashTree(if_ids, b"s", hash_func)
        inst._n_epochs = 1
        inst._depth = 2
        # Call
        inst.create_tree(if_ids)
        # Tests
        expected = [b"10s1020s2030s300", b"10s1020s20", b"30s300", b"10s10",
                    b"20s20", b"30s30", b"0"]
        ntools.eq_(inst._nodes, expected)


class TestHashTreeGetProof(object):
    """
    Unit test for lib.crypto.hash_tree.HashTree.get_proof
    """
    @patch("lib.crypto.hash_tree.HashTree._setup", autospec=True)
    def test(self, _):
        # Setup
        if_ids = [1, 2, 3]
        hashes = [b"s10", b"10s10", b"s20", b"20s20", b"s30", b"30s30",
                  b"0", b"30s300", b"10s1020s20", b"10s1020s2030s300", b"s20"]
        hash_new = create_mock_full({"digest()...": hashes})
        hash_func = create_mock_full({"new()": hash_new})
        inst = HashTree(if_ids, b"s", hash_func)
        inst._n_epochs = 1
        inst._depth = 2
        inst.create_tree(if_ids)
        # Call
        proof = inst.get_proof(2, 0, "prev", "next")
        # Tests
        ntools.eq_(proof.p.nonce, b"s20")
        ntools.eq_(proof.p.siblings[0].isLeft, True)
        ntools.eq_(proof.p.siblings[0].hash, b"10s10")
        ntools.eq_(proof.p.siblings[1].isLeft, False)
        ntools.eq_(proof.p.siblings[1].hash, b"30s300")


class TestConnectedHashTreeUpdate(object):
    """
    Unit test for lib.crypto.hash_tree.ConnectedHashTree.update
    """
    def test(self):
        # Setup
        if_ids = [23, 35, 120]
        initial_seed = b"qwerty"
        inst = ConnectedHashTree(if_ids, initial_seed)
        root1_before_update = inst._ht1._nodes[0]
        root2_before_update = inst._ht2._nodes[0]
        # Call
        new_tree = inst.get_next_tree(if_ids, b"new!!seed")
        inst.update(new_tree)
        # Tests
        root0_after_update = inst._ht0_root
        root1_after_update = inst._ht1._nodes[0]
        ntools.eq_(root1_before_update, root0_after_update)
        ntools.eq_(root2_before_update, root1_after_update)


class TestConnectedHashtreeGetPossibleHashes(object):
    """
    Unit test for lib.crypto.hash_tree.ConnectedHashTree.get_possible_hashes
    """
    def test(self):
        # Setup
        siblings = []
        siblings.append(create_mock_full({"isLeft": True, "hash": "10s10"}))
        siblings.append(create_mock_full({"isLeft": False, "hash": "30s300"}))
        p = create_mock_full(
            {"ifID": 2, "epoch": 0, "nonce": b"s20", "siblings": siblings,
             "prevRoot": "p", "nextRoot": "n"})
        revProof = create_mock_full({"p": p})
        hashes = ["20s20", "10s1020s20", "10s1020s2030s300",
                  "p10s1020s2030s300", "10s1020s2030s300n"]
        hash_new = create_mock_full({"digest()...": hashes})
        hash_func = create_mock_full({"new()": hash_new})
        # Call
        hash01, hash12 = ConnectedHashTree.get_possible_hashes(
            revProof, hash_func)
        # Tests
        ntools.eq_(hash01, "p10s1020s2030s300")
        ntools.eq_(hash12, "10s1020s2030s300n")


class TestConnectedHashTreeUpdateAndVerify(object):
    """
    Unit tests for lib.crypto.hash_tree.ConnectedHashTree.verify
    used along with lib.crypto.hash_tree.ConnectedHashTree.update
    """
    def test_one_timestep(self):
        # Check that the revocation proof is verifiable across T and T+1.
        # Setup
        if_ids = [23, 35, 120]
        initial_seed = b"qwerty"
        inst = ConnectedHashTree(if_ids, initial_seed)
        root = inst.get_root()
        # Call
        next_tree = inst.get_next_tree(if_ids, b"new!!seed")
        inst.update(next_tree)
        # Tests
        proof = inst.get_proof(35)  # if_id = 35.
        ntools.eq_(ConnectedHashTree.verify(proof, root), True)

    def test_two_timesteps(self):
        # Check that the revocation proof is "NOT" verifiable across T and T+2.
        # Setup
        if_ids = [23, 35, 120]
        initial_seed = b"qwerty"
        inst = ConnectedHashTree(if_ids, initial_seed)
        root = inst.get_root()
        # Call
        new_tree = inst.get_next_tree(if_ids, b"newseed.@1")
        inst.update(new_tree)
        new_tree = inst.get_next_tree(if_ids, b"newseed.@2")
        inst.update(new_tree)
        # Tests
        proof = inst.get_proof(35)  # if_id = 35.
        ntools.eq_(ConnectedHashTree.verify(proof, root), False)


class TestConnectedHashTreeVerifyEpoch(object):
    """
    Unit test for lib.crypto.hash_tree.ConnectedHashTree.verify_epoch
    """
    @patch("time.time", autospec=True)
    def test_same_epoch(self, time):
        # Setup
        time.return_value = HASHTREE_EPOCH_TIME + HASHTREE_EPOCH_TOLERANCE + 1
        # Call and tests
        ntools.eq_(ConnectedHashTree.verify_epoch(1), True)
        ntools.eq_(ConnectedHashTree.verify_epoch(2), False)

    @patch("time.time", autospec=True)
    def test_different_epoch(self, time):
        # Setup
        time.return_value = HASHTREE_EPOCH_TIME + 1
        # Call and test
        ntools.eq_(ConnectedHashTree.verify_epoch(0), True)
        ntools.eq_(ConnectedHashTree.verify_epoch(1), True)


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
