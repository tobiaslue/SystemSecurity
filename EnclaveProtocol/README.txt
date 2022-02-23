### Steps to compile and run your project here ###

### App B has to be started first ###
cd Enclave_B
make SGX_MODE=SIM
./app

### App A has to be started second ###
cd ../Enclave_A
make SGX_MODE=SIM
./app

//use this to mark code regions as specified in the assignment sheet
/*************************
 * BEGIN [region that you're annotating, e.g. E_B decrypt challenge]
 *************************/
 <your code here>
/*************************
 * END [region that you're annotating, e.g. E_B decrypt challenge]
 *************************/