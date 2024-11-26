# `entropy-create-test-keyshares`

This is used to create sets of pre-generated keyshares. These are used in some of the `entropy-tss`
tests to speed up the test by not needing to run a distributed key generation during the test.

There are different keyshare sets for 'test' or 'production' parameters used by Synedrion. Test
parameters are less secure but mean that the protocols run much faster.
