# `entropy-create-test-keyshares`

This is used to create sets of pre-generated keyshares. These are used in some of the `entropy-tss`
tests to speed up the test by not needing to run a distributed key generation during the test.

Since keyshares are linked to the identities of the holders, and the initial signer set is selected
randomly during the test, there is one keyshare set generated per possible combination of initial
signers.

Since we have 4 nodes, and 3 signers, we refer to each set by the name of the node who is **not** in
the signer set (which is the one who will act as the relayer node).

So set 'alice' consists of ['bob', 'charlie', 'dave'] and set 'bob' consists of ['alice', 'charlie',
dave'], etc.

There are also different keyshare sets for 'test' or 'production' parameters used by Synedrion. Test
parameters are less secure but mean that the protocols run much faster.
