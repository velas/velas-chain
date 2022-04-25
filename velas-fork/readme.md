# Velas fork maintenance guide and tools

Velas is a fork of Solana blockchain.
This document will describe how we treat code, and manage branches.

## Velas releases
Solana has edge/beta/stable branches:
- edge is only used on testnet;
- beta is some kind of migration, early adoption of edge codebase to the mainnet;
- stable is widespread on mainnet

Fixes are ported on all three branches edge/beta/stable.
New features are only mooved to the edge.

**In Velas Some of Solana changes (especially security fixes) are ported dirrectly to Velas repository.**

In Velas we use `develop` branch as a single source of code.
- Our develop branch are tested on testnet and devnet.
- Realeases are tagged dirrectly on develop, and only those releases are used by validator.
- We don't have multi branches for testnet/mainnet purposes, because most of our network related features are already tested on solana edge branch.


## Merging solana features
At some point of time we do a "full-update" which merge all solana changes to the velas develop.

Merging are done using `git merge` and most of conflicts should be resolved manually, to make it easier for person who are resolving this conflicts.
In this document we describe some common parts that can be treat differently, and trying to document what changes are done in solana codebase by velas.

Short algorithm describing how to handle full update:
1. Pointing out what files was changed in velas since last full-update.
For doing this we save special file called `solana-base` which contain single line - solana release tag that was used during last update.
** Note: ':!docs' ':!explorer' ':!web3.js' - are ignored folders
`git diff $TAG --numstat -- ':!docs' ':!explorer' ':!web3.js'`
2. Ignore removed files in merge.
We remove js related stuff from our monorepo
`git rm -rf docs web3.js explorer`
3. Ignore crates that was rewritted by us 
`git checkout --theirs install`
4. Ignore files that wasnt modified by velas (checkout number 1 of this algorithm)
`git checkout --theirs __`
5. Solve remaining conflicts by groups:
To solve conflicts we recommend to use some kind of 3way merging tools, like beyond compare
a) Solve Cargo.toml conflicts - need to automatize this - usually it contains version bumping, and some adding of evm-utils that can conflict with other dependencies addings. 
b) Solve core, sdk and runtime, this 3 crates contain a lot of integration points and should be carefully merged most of changed files are listed in `many-changes.txt`
c) Solve remaining parts.
6. feature_set.rs - Porting new features from solana has different rules that just regular merge:
a) Make sure that no legacy features was removed before activation on mainnet/testnet - it can lead to instability.
b) Make sure that all public keys was changed - we have different secret keys.

1-4 of this algorithm was implemented in shell script called `git-merge-cleanup.sh`


### Review of merge

It's hard to review all changes, because github will visualize all the changes from merged branch.
To easier review, compare two diffs of `solana-base` (checkout solana-base file) and `develop` before and after merging,
they should be more or less the same.

### Finalizing merge

During solana merge, develop can have new features. Because we have single branch this can make some problems.
As algorithm that solve problems, use follow:
1. After merge is done create a new version branch '0.3', '0.5', etc. from latest `develop`.
2. Create a new tag and release latest version.
3. Rename merge branch to be `develop` all patches that was merged in latest release should be also cherry-picked to merged branch.
4. New pre-release with bumped version should be released for future tests.



## Velas versioning
Currently we dont use major version, and instead using minor and patch.
- Patch version are used when some small changes or feature is implemented.
- Major version are increased when "full-update" is done, or when some backward incompatible change is done - like snapshot version bumping.
