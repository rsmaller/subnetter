#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <libgen.h>
#include <time.h>
#include <math.h>

typedef union { // data containing an IP address. 
    uint32_t IP; // represents IP as a 32-bit number. useful for IP addition.
    uint8_t octets[4]; // per-octet IP. useful for IP construction.
} ipaddr;

char* programName;
int binaryFlag = 0;
int helpFlag = 0;
int debug = 1;
static char *(*IPtoString)(ipaddr);
static char *(*ChangingIPtoString)(ipaddr, int);

typedef struct subnetAttributes { // return type of function that calculates subnet data based on a subnet mask.
    unsigned long long int blockSize;
    unsigned long long int numberOfSubnets;
    int CIDRMask;
    int usableHosts;
} subnetAttributes;

static void usage(char *errorReason) { // many functions call back to this function when they receive input that is not a valid IP, Subnet Mask, or CIDR Mask.
    printf("Usage: ./%s IP_ADDRESS SUBNET_OR_CIDR_MASK_1 SUBNET_OR_CIDR_MASK_2 <-b(inary)|-h(elp)>\n", programName);
    if (debug)
        printf("Error reason: %s\n", errorReason);
    exit(0);
}

static void help(void) {
    printf("This program takes in a series of arguments, the first being an IP address.\n\
This IP address is used in conjunction with a subnet mask to calculate and display one or more subnets.\n\
This program will display the following information:\n\
    -The block size (number of IP addresses) of each subnet it generates\n\
    -The number of usable hosts in each subnet\n\
    -The network and broadcast addresses of each subnet\n\
    -The starting and ending addresses of each subnet\n\n\
This program requires an IP address and subnet mask to present any meaningful subnet information.\n\
If the program does not receive enough information from the user or the information it does receive is invalid,\n\
the user will be prompted with a usage message.\n\
(Optionally, the user can provide two subnet masks, which allows for VLSM. \n\
When using two subnet masks, make sure the first subnet mask entered has a larger block size than the second.)\n\n\
An example of how this program might be run is as follows:\n\
    %s 192.168.1.1 255.255.255.0\n\n\
It is also worth noting that subnet masks can be entered in CIDR notation, so the following is also valid:\n\
    %s 192.168.1.1 24\n\n\
The above commands would output the following information (Note that the information is annotated here):\n\
1 Subnet(s) Total, 256 IP(s) Per Subnet, 254 Usable Host(s) Per Subnet\n\
255.255.255.0[/24] (The subnet mask in both regular and CIDR notation)\n\
192.168.1.0/24 -> 192.168.1.x/24 (VLSM information)\n\
-------------------------------------------------------------------\n\
192.168.1.0/24: (The network address of the subnet and the CIDR mask of the subnet)\n\
        192.168.1.1 - 192.168.1.254 (The address range of the subnet)\n\
        192.168.1.255 broadcast (The broadcast address of the subnet)\n\
0.001000 seconds used to subnet (How long the program took to run)\n\n", programName, programName);
exit(0);
}

static int getSignificantOctets(int CIDRMask) {
    if (CIDRMask == 0)
        return 0;
    return (int)ceil((double)(CIDRMask / 8));
}

static char *IPtoRegularString(ipaddr IP) {
    char *returnValue = (char *)malloc((size_t)16);
    sprintf(returnValue, "%d.%d.%d.%d", IP.octets[3], IP.octets[2], IP.octets[1], IP.octets[0]);
    return returnValue;
}

static char *IPtoChangingRegularString(ipaddr IP, int CIDRMask) {
    char *returnValue = (char *)malloc((size_t)16);
    int significantOctets = getSignificantOctets(CIDRMask);
    int changingHostOctets = 4 - significantOctets;
    switch (changingHostOctets){
        case 4:
            sprintf(returnValue, "x.x.x.x");
            break;
        case 3:
            sprintf(returnValue, "%d.x.x.x", IP.octets[3]);
            break;
        case 2:
            sprintf(returnValue, "%d.%d.x.x", IP.octets[3], IP.octets[2]);
            break;
        case 1:
            sprintf(returnValue, "%d.%d.%d.x", IP.octets[3], IP.octets[2], IP.octets[1]);
            break;
        case 0:
            sprintf(returnValue, "%d.%d.%d.%d", IP.octets[3], IP.octets[2], IP.octets[1], IP.octets[0]);
            break;
    }
    return returnValue;
}

// debug only
// static void printIPDecimal(ipaddr IP) {
//     printf("%u", IP.IP);
// }

static char *octetToBinaryString(unsigned char intArg) {
    char *binaryForm = (char *)malloc((size_t)9);
    for (int i=0; i<9; i++) {
        binaryForm[i] = 0;
    }
    int bitshiftOperand = ((int)sizeof(unsigned char) * 8) - 1;
    while (bitshiftOperand >= 0) {
        if (intArg >= (unsigned char)1<<bitshiftOperand) {
            intArg -= ((unsigned char)1<<bitshiftOperand);
            strcat(binaryForm, "1");
        } else {
            strcat(binaryForm, "0");
        }
        bitshiftOperand--;
    }
    return binaryForm;
}

static char *changingOctetToBinaryString(unsigned char intArg, int changingBits) {
    char *binaryForm = (char *)malloc((size_t)9);
    for (int i=0; i<9; i++) {
        binaryForm[i] = 0;
    }
    int unchangingBits = 8 - changingBits;
    int bitshiftOperand = ((int)sizeof(unsigned char) * 8) - 1;
    for (int i=0; i<unchangingBits; i++) {
        if (intArg >= (unsigned char)1<<bitshiftOperand) {
            intArg -= ((unsigned char)1<<bitshiftOperand);
            strcat(binaryForm, "1");
        } else {
            strcat(binaryForm, "0");
        }
        bitshiftOperand--;
    }
    for (int i=0; i<changingBits; i++) {
        strcat(binaryForm, "x");
    }
    return binaryForm;
}

static char *IPtoBinaryString(ipaddr IP) {
    unsigned int IPNumber = IP.IP;
    char *binaryForm = (char *)malloc((size_t)36);
    for (int i=0; i<36; i++) {
        binaryForm[i] = 0;
    }
    int originalBitshiftOperand = ((int)sizeof(unsigned int) * 8) - 1;
    int bitshiftOperand = originalBitshiftOperand;
    while (bitshiftOperand >= 0) {
        if ((bitshiftOperand + 1) % 8 == 0 && bitshiftOperand != originalBitshiftOperand) {
            strcat(binaryForm, ".");
        }
        if (IPNumber >= (unsigned int)1<<bitshiftOperand) {
            IPNumber -= ((unsigned int)1<<bitshiftOperand);
            strcat(binaryForm, "1");
        } else {
            strcat(binaryForm, "0");
        }
        bitshiftOperand--;
    }
    return binaryForm;
}

static char *IPtoChangingBinaryString(ipaddr IP, int CIDRMask) {
    char *returnValue = (char *)malloc((size_t)36);
    int significantOctets = getSignificantOctets(CIDRMask);
    int changingHostOctets = 4 - significantOctets;
    int changingBits = 32 - CIDRMask;
    switch (changingHostOctets){
        case 4:
            sprintf(returnValue, "%s.xxxxxxxx.xxxxxxxx.xxxxxxxx", changingOctetToBinaryString(IP.octets[3], changingBits - 24));
            break;
        case 3:
            sprintf(returnValue, "%s.%s.xxxxxxxx.xxxxxxxx", octetToBinaryString(IP.octets[3]), changingOctetToBinaryString(IP.octets[2], changingBits - 16));
            break;
        case 2:
            sprintf(returnValue, "%s.%s.%s.xxxxxxxx", octetToBinaryString(IP.octets[3]), octetToBinaryString(IP.octets[2]), changingOctetToBinaryString(IP.octets[1], changingBits - 8));
            break;
        case 1:
            sprintf(returnValue, "%s.%s.%s.%s", octetToBinaryString(IP.octets[3]), octetToBinaryString(IP.octets[2]), octetToBinaryString(IP.octets[1]), changingOctetToBinaryString(IP.octets[0], changingBits));
            break;
        case 0:
            sprintf(returnValue, "%s.%s.%s.%s", octetToBinaryString(IP.octets[3]), octetToBinaryString(IP.octets[2]), octetToBinaryString(IP.octets[1]), octetToBinaryString(IP.octets[0]));
            break;
    }
    return returnValue;
}

static void verifyOctet(int IPOctet) {
    if (IPOctet > 255) 
        usage("IPOctet bigger than 255");
    else if (IPOctet < 0) 
        usage("IPOctet less than 0");
}

static int constructOctetFromString(char *IPString) { // converts a string into an IP octet after ensuring string is a valid octet.
    int returnInt = atoi(IPString);
    verifyOctet(returnInt);
    return returnInt;
}

static int* splitIntoOctets(char* IPString) {
    char returnStringArray[4][4] = {"", "", "", ""};
    int stringLength = strlen(IPString);
    int index = 0;
    int characterIndex = 0;
    for (int i=0; i<stringLength; i++) {
        if (IPString[i] != '.') {
            returnStringArray[index][characterIndex] = IPString[i];
            characterIndex += 1;
        }
        else {
            index += 1;
            characterIndex = 0;
        }
    }
    if (index != 3)
        usage("Wrong number of dots in IP argument");
    int *returnOctetArray = (int *)malloc(sizeof(int)*4);
    for (int i=0; i<4; i++)
        returnOctetArray[i] = constructOctetFromString(returnStringArray[i]);
    return returnOctetArray;
}

static ipaddr constructIP(char* IPString) {
    ipaddr returnIP;
    int *newOctets = splitIntoOctets(IPString);
    returnIP.octets[0] = newOctets[3];
    returnIP.octets[1] = newOctets[2];
    returnIP.octets[2] = newOctets[1];
    returnIP.octets[3] = newOctets[0];
    free(newOctets);
    return returnIP;
}

static int getCIDRMask(ipaddr subnetMask) {
    switch (subnetMask.IP) {
        case 0:          return 0;  case 2147483648: return 1; 
        case 3221225472: return 2;  case 3758096384: return 3;
        case 4026531840: return 4;  case 4160749568: return 5;
        case 4227858432: return 6;  case 4261412864: return 7;
        case 4278190080: return 8;  case 4286578688: return 9;
        case 4290772992: return 10; case 4292870144: return 11;
        case 4293918720: return 12; case 4294443008: return 13;
        case 4294705152: return 14; case 4294836224: return 15;
        case 4294901760: return 16; case 4294934528: return 17;
        case 4294950912: return 18; case 4294959104: return 19;
        case 4294963200: return 20; case 4294965248: return 21;
        case 4294966272: return 22; case 4294966784: return 23;
        case 4294967040: return 24; case 4294967168: return 25;
        case 4294967232: return 26; case 4294967264: return 27;
        case 4294967280: return 28; case 4294967288: return 29;
        case 4294967292: return 30; case 4294967294: return 31;
        case 4294967295: return 32; default:         return -1;
    }
}

static int isSubnetMask(ipaddr subnetMask) {
    int CIDRMask = getCIDRMask(subnetMask);
    if (CIDRMask <= 32 && CIDRMask >= 0)
        return 1;
    else
        return 0;
}

static int isCIDRMask(int CIDRMask) {
    if (CIDRMask <= 32 && CIDRMask >= 0)
        return 1;
    else   
        return 0;
}

static ipaddr CIDRToSubnetMask(int CIDRMask) {
    ipaddr returnIP;
    int invertedMask = 32 - CIDRMask;
    unsigned long long int myUnsignedInt1 = ((unsigned long long int)1<<invertedMask) - 1;
    returnIP.IP = (uint32_t)~myUnsignedInt1;
    return returnIP;
}

static subnetAttributes getSubnetInfo(ipaddr subnetMask) {
    int CIDRMask = getCIDRMask(subnetMask);
    unsigned long long int blockSize = (unsigned long long int)1<<(32-CIDRMask);
    unsigned long long int numberOfSubnets = (unsigned long long int)1<<CIDRMask;
    int usableHosts = 0;
    if (blockSize > 2)
        usableHosts = blockSize - 2;
    subnetAttributes returnValue;
    returnValue.blockSize = blockSize;
    returnValue.numberOfSubnets = numberOfSubnets;
    returnValue.CIDRMask = CIDRMask;
    returnValue.usableHosts = usableHosts;
    return returnValue;
}

static void printOutSubnet(ipaddr mainIP, ipaddr subnetMask) {
    ipaddr networkIP;
    ipaddr startingIP;
    ipaddr endingIP;
    ipaddr broadcastIP;
    subnetAttributes subnetAttributes = getSubnetInfo(subnetMask);
    int CIDRMask = subnetAttributes.CIDRMask;
    unsigned long long int blockSize = subnetAttributes.blockSize;
    networkIP.IP = mainIP.IP & subnetMask.IP;
    switch (CIDRMask) {
        case 31:
            startingIP.IP = networkIP.IP;
            broadcastIP.IP = networkIP.IP;
            endingIP.IP = networkIP.IP + 1;
            printf("%s/%d:\n\t%s - %s\n", IPtoString(networkIP), CIDRMask, IPtoString(startingIP), IPtoString(endingIP));
            break;
        case 32:
            startingIP.IP = networkIP.IP;
            broadcastIP.IP = networkIP.IP;
            endingIP.IP = broadcastIP.IP;
            printf("%s/%d\n", IPtoString(networkIP), CIDRMask);
            break;
        default:
            startingIP.IP = networkIP.IP + 1;
            broadcastIP.IP = networkIP.IP + blockSize - 1;
            endingIP.IP = broadcastIP.IP - 1;
            printf("%s/%d:\n\t%s - %s\n\t%s broadcast\n", IPtoString(networkIP), CIDRMask, IPtoString(startingIP), IPtoString(endingIP), IPtoString(broadcastIP));
            break;
    }
}

static void VLSM(ipaddr mainIP, ipaddr subnetMask1, ipaddr subnetMask2) { // subnetMask1 should contain larger block sizes than subnetMask2
    subnetAttributes subnet1Details = getSubnetInfo(subnetMask1);
    int subnet1CIDRMask = subnet1Details.CIDRMask;
    subnetAttributes subnet2Details = getSubnetInfo(subnetMask2);
    int subnet2CIDRMask = subnet2Details.CIDRMask;
    unsigned long long int subnet2BlockSize = subnet2Details.blockSize;
    unsigned long long int subnet2UsableHosts = subnet2Details.usableHosts;
    int networkMagnitudeDifference = subnet2CIDRMask - subnet1CIDRMask;
    unsigned long long int numberOfSubnets = (unsigned long long int)1<<networkMagnitudeDifference;
    ipaddr mainNetworkIP;
    mainNetworkIP.IP = mainIP.IP & subnetMask1.IP;
    printf("%lld Subnet(s) Total, %lld IP(s) Per Subnet, %lld Usable Host(s) Per Subnet\n%s[/%d]", numberOfSubnets, subnet2BlockSize, subnet2UsableHosts, IPtoString(subnetMask1), subnet1Details.CIDRMask);
    if (subnetMask1.IP != subnetMask2.IP) {
        printf(" -> %s[/%d]\n", IPtoString(subnetMask2), subnet2Details.CIDRMask); 
    } else {
        printf("\n");
    }
    printf("%s/%d -> %s", IPtoString(mainNetworkIP), subnet1CIDRMask, ChangingIPtoString(mainIP, subnet2CIDRMask));
    if (!binaryFlag)
        printf("/%d\n-------------------------------------------------------------------\n", subnet2CIDRMask);
    else 
        printf("/%d\n-----------------------------------------------------------------------------------------\n", subnet2CIDRMask);
    for (unsigned long long int i=0; i<numberOfSubnets; i++) {
        printOutSubnet(mainNetworkIP, subnetMask2);
        mainNetworkIP.IP += subnet2BlockSize;
    }
}

static void verifyIPArguments(int argc, char *argv[]) {
    for (int i=1; i<argc; i++) {
        if (strlen(argv[i]) > 15)
            usage("Argument in program is too large");
    }
}

static ipaddr *getSubnetMasksFromArguments(int argc, char *argv[]) {
    ipaddr *returnArray = (ipaddr *)malloc(sizeof(ipaddr) * 2);
    ipaddr subnetMask1;
    if (isCIDRMask(atoi(argv[2]))) {
        subnetMask1 = CIDRToSubnetMask(atoi(argv[2]));
    }
    else {
        subnetMask1 = constructIP(argv[2]);
        if (!isSubnetMask(subnetMask1))
            usage("First argument is not a valid subnet mask");
    }
    ipaddr subnetMask2;
    if (argc == 3)
        subnetMask2.IP = subnetMask1.IP;
    else
        if (isCIDRMask(atoi(argv[3]))) {
            subnetMask2 = CIDRToSubnetMask(atoi(argv[3]));
        }
        else {
            subnetMask2 = constructIP(argv[3]);
            if (!isSubnetMask(subnetMask2))
                subnetMask2.IP = subnetMask1.IP;
        }
    returnArray[0] = subnetMask1;
    returnArray[1] = subnetMask2;
    if (returnArray[0].IP > returnArray[1].IP)
        returnArray[1].IP = returnArray[0].IP;
    return returnArray;
}

static void checkArgsAndSetPointers(int argc, char *argv[]) {
    for (int i=0; i<argc; i++) {
        if (!strcmp(argv[i], "-h"))
            helpFlag = 1;
        if (!strcmp(argv[i], "-b"))
            binaryFlag = 1;
    }
    if (helpFlag) {
        help();
    }
    if (binaryFlag) {
        IPtoString = &IPtoBinaryString;
        ChangingIPtoString = &IPtoChangingBinaryString;
    } else {
        IPtoString = &IPtoRegularString;
        ChangingIPtoString = &IPtoChangingRegularString;
    }
}

int main(int argc, char *argv[]) {
    programName = basename(argv[0]);
    checkArgsAndSetPointers(argc, argv);
    clock_t startingClock, endingClock;
    if (argc < 3)
        usage("Wrong number of arguments");
    verifyIPArguments(argc, argv);
    ipaddr mainIP = constructIP(argv[1]);
    ipaddr *subnetArray = getSubnetMasksFromArguments(argc, argv);
    ipaddr subnetMask1 = subnetArray[0];
    ipaddr subnetMask2 = subnetArray[1];
    free(subnetArray);
    if (subnetMask1.IP > subnetMask2.IP)
        usage("First argument has smaller block size than second argument");
    startingClock = clock();
    VLSM(mainIP, subnetMask1, subnetMask2);
    endingClock = clock();
    double timeTotal = (double)(endingClock - startingClock) / CLOCKS_PER_SEC;
    printf("%f seconds used to subnet\n", timeTotal);
}
