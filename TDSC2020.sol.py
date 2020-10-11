pragma
solidity >= 0.4
.22 < 0.6
.0;

contract
write
{
    mapping(bytes16= > bytes16) public
blockindex;
int
public
is_equal;
// bytes16
public
end_xor;
mapping(uint= > bytes16) public
blockxor;
bytes16
public
finish_xor;
// bytes16
public
recordtoken;

function
setbatch(bytes16[]
memory
ctoken, bytes16[]
memory
dhash, uint
len) public
{
for (uint i=0; i < len; i++) {
    bytes16 x=ctoken[i];
bytes16 y=dhash[i];
blockindex[x]=y;
}
}


function set(bytes16 ctoken, bytes16 dhash) public{
blockindex[ctoken]=dhash;
}



function batch_gethash(bytes16[] memory enfile, uint len, uint blocknum) public{
bytes16 xor;
for (uint i=0; i < len; i++) {
if (i == 0){
xor=  enfile[i];
}
else
{
bytes16 hashfileID = enfile[i];
xor=xor ^ hashfileID;
}
}
blockxor[blocknum]=xor;
// end_xor=xor;
}


function getlastxor(uint totalnumber) public{
bytes16 xor;

for (uint i=0; i <= totalnumber; i++) {

if (i == 0){
xor=blockxor[i];
}
else {
xor=xor ^ blockxor[i];
}
}

finish_xor=xor;
}



function try_whether_equal(bytes16 token) public returns (int current_xor){

if (blockindex[token] == finish_xor)
{
is_equal=1;
}
else {
is_equal=0;
}

}

function check_equal_or_not() public view returns (int){
return is_equal;
}

// function
gettoken(bytes16
token) public
view
returns(bytes32)
{
// return blockindex[token];
//}

// function
check_()
public
view
returns(bytes32)
{
// return finish_xor;
//}

// function
equal_or_not(bytes32
recordhash ) public
returns(int
current_xor){

// if (recordhash == finish_xor)
    // {
       // is_equal = 1;
    //}
    // else {
            // is_equal = 0;
    //}

    //}

    // function
    get_computexor()
    public
    view
    returns(bytes32)
    {
    // return end_xor;
    //}

    }





