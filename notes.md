# Unresolved Subchain Issues

1. IX: Modify subchain config
2. 100 blocks limit in blockstore
3. In subchain-manager - print none fields for account alloc
4. Update subchain docs at docs.velas.com
5. Review warnings of cargo build
6. cleanup default subchains
7. TODO(L): assert, subchain_roots=empty on !feature_subchain
8. TODO(H): Add incremental snapshoting
9. TODO(L): Replace root/db/bank by root-guard.
10. TODO(H): Save last hashes list, to perform cleanup if it was recoverable error.
11. a. TODO(C): Remove swap precompile for subchain.
    b. Make sure precompile section is covered with tests
12. TODO(H): Add support of block_by_num state on subchain
13. TODO(H): get from state account
14. TODO:(L): activate updated precompiles through a runtime feature

--

1.  Reverted transaction processing 
2.  geth --follow
3.  new eip tx format
4.  new evm version

fix cleanup old blocks for subchain (search todo!())