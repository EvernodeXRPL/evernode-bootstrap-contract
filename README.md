# Evernode bootstrap contract
Evernode bootstrap contract used by Sashimono as the default contract of new HotPocket instances. This contract's purpose is to accept the user-defined contract bundle as a user input and replace itself with the supplied contract bundle. Only the user public key supplied as a cli argument will be allowed to submit the contract bundle.

## Build
```
cmake .
make
```
