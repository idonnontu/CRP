#include<stdlib.h>
#include<stdio.h>
#include<string.h>
#include<time.h>
#include<limits.h>

#define MAX_LINE_LENGTH 100 
// #define MAX_MERGE_COST 
typedef struct field field;
struct field{
    unsigned int ip;
    unsigned int length;
    field *next;
};

field *createField(int num){
    field *tempField = (field *)malloc(sizeof(field) * num);
    if(tempField == NULL){
        printf("create field fail");
        exit(1);
    }
    for(int i = 0; i < num; i++)
        tempField[i].next = NULL;
    return tempField;
}

typedef struct rule rule;
struct rule{
    field source;
    field destination;
    rule *next;
};

typedef struct{
    rule *table;
    int maxRuleNumber;
    int nowRuleNum;
}ruleTable;

int compare2IpSame(unsigned int ip1, unsigned int ip2, unsigned int compareBit);

ruleTable *createRuleTable(int ruleNumber){
    ruleTable *tempTable = (ruleTable *)malloc(sizeof(ruleTable));
    if(tempTable == NULL){
        printf("create rule table fail\n");
        exit(1);
    }
    tempTable->maxRuleNumber = ruleNumber;
    tempTable->nowRuleNum = 0;
    tempTable->table = (rule *)malloc(sizeof(rule) * ruleNumber);
    if(tempTable->table == NULL){
        printf("create rule table fail\n");
        exit(1);
    }
    return tempTable;
}

void freeRuleTable(ruleTable *ruleTable){
    free(ruleTable->table);
    free(ruleTable);
}

field *ipStrToField(char *targetIP){
    field *tempField = createField(1);
    char *token = strtok(targetIP, "/");
    token = strtok(NULL, "/");
    tempField->length = atoi(token);

    tempField->ip = 0;
    for(int i = 0; i < 4; i++){
        if(i == 0)
            token = strtok(targetIP, "./");
        else
            token = strtok(NULL, "./");
        unsigned int tempInt = atoi(token);
        tempField->ip += tempInt;
        if(i != 3)
            tempField->ip <<= 8;
        // printf("push %u \n", tempInt);
    }
    // for(int bit = 0; bit < 32; bit++)
    //     printf("%d", (unsignedIP >> (31 - bit)) & 0x00000001);
    // printf("\n");
    return tempField;
}

int isLegalRule(ruleTable *ruleTable, field *srcField, field *dstField){
    // check rule number doesn't hit maximum
    if(ruleTable->nowRuleNum >= ruleTable->maxRuleNumber){
        printf("rule table reach max!!!\n");
        return 0;
    }

    // check no exist rules has the same source ip and destination ip like input rule
    for(int i = 0; i < ruleTable->nowRuleNum; i++){
        int sameSrc = 0, sameDst = 0; 
        if(ruleTable->table[i].source.ip == srcField->ip &&
           ruleTable->table[i].source.length == srcField->length)
            sameSrc = 1;
        if(ruleTable->table[i].destination.ip == dstField->ip &&
           ruleTable->table[i].destination.length == dstField->length)
            sameDst = 1;
        if(sameSrc && sameDst)
            return 0;
    }
    return 1;
}

void ruleTablePush(ruleTable *ruleTable, field *srcField, field *dstField){
    if(isLegalRule(ruleTable, srcField, dstField)){
        ruleTable->table[ruleTable->nowRuleNum].source = *srcField;
        ruleTable->table[ruleTable->nowRuleNum].destination = *dstField;
        ruleTable->nowRuleNum++;
        free(srcField);
        free(dstField);
    }
}

void readInRule(char *rulePath, ruleTable *ruleTable){
    // Open the input file in read mode
    FILE *file = fopen(rulePath, "r");
    if (file == NULL) {
        perror("Error opening file");
        exit(1);
    }

    // Buffer to hold each line
    char line[MAX_LINE_LENGTH];

    // Read each line from the file
    while (fgets(line, sizeof(line), file)) {
        char src_ip[20], dst_ip[20], src_port_range[20], dst_port_range[20], protocol[20], flags[20];

        // Parse the line and store the values into respective variables
        if (sscanf(line, "%s %s %s %s %s %s",
                   src_ip, dst_ip, src_port_range, dst_port_range, protocol, flags) == 6) {
            // Print the parsed data
            // printf("Source IP: %s\n", src_ip);
            // printf("Destination IP: %s\n", dst_ip);
            // printf("Source Port Range: %s\n", src_port_range);
            // printf("Destination Port Range: %s\n", dst_port_range);
            // printf("Protocol: %s\n", protocol);
            // printf("Flags: %s\n\n", flags);
        } else {
            fprintf(stderr, "Error parsing line: %s\n", line);
        }

        field *srcField = ipStrToField(src_ip);
        field *dstField =  ipStrToField(dst_ip);
        ruleTablePush(ruleTable, srcField, dstField);
        // for(int bit = 0; bit < 32; bit++)
        //     printf("%d", (unsignedSrc >> (31 - bit)) & 0x00000001);
        // break;
    }
    // Close the file
    fclose(file);
}

void printRuleTable(ruleTable *ruleTable){
    for(int i = 0 ; i < ruleTable->nowRuleNum; i++){
        printf("id:%d\n", i);
        unsigned int srcIp = ruleTable->table[i].source.ip;
        unsigned int dstIp = ruleTable->table[i].destination.ip;
        for(int bit = 0; bit < 32; bit += 8)
            printf("%u.", (srcIp >> (24 - bit)) & 0x000000ff);
        printf("len:%u\n", ruleTable->table[i].source.length);

        for(int bit = 0; bit < 32; bit += 8)
            printf("%u.", (dstIp >> (24 - bit)) & 0x000000ff);
        printf("len:%u\n", ruleTable->table[i].destination.length);
    }
}

// prefix length tuple
typedef struct plt plt;
struct plt{
    unsigned int srcLen, dstLen;
    rule *ruleList;
    int ruleNum;
    plt *next;
    field *source, *dest;
    int sourceNum, destNum;

    rule **hash;
};

plt *createPLT(){
    plt *tempPLT = (plt *)malloc(sizeof(plt));
    if(tempPLT == NULL){
        printf("create plt fail");
        exit(1);
    }
    tempPLT->srcLen = -1;
    tempPLT->dstLen = -1;
    tempPLT->ruleNum = 0;
    tempPLT->next = NULL;

    tempPLT->sourceNum = 0;
    tempPLT->destNum = 0;
    tempPLT->source = NULL;
    tempPLT->dest = NULL;

    tempPLT->ruleList = NULL;
    return tempPLT;
}

void getNonRepeatField(plt *pltPtr, field *srcPtr, field *dstPtr);

void pltAddSource(plt *pltPtr, field *source){
    if(pltPtr->sourceNum == 0){
        pltPtr->source = (field *)malloc(sizeof(field));
        if(pltPtr->source == NULL){
            printf("plt add source field fail!\n");
            exit(1);
        }
        *(pltPtr->source) = *source;
        pltPtr->sourceNum++;
    }else{
        field *tempField = (field *)malloc( sizeof(field) * (pltPtr->sourceNum+1) );
        if(tempField == NULL){
            printf("plt add source field fail!\n");
            exit(1);
        }
        int repeat = 0;
        for(int i = 0 ; i < pltPtr->sourceNum; i++){
            if(pltPtr->source[i].length == source->length && compare2IpSame(pltPtr->source[i].ip, source->ip, source->length)){
                repeat = 1;
                break;
            }
            tempField[i] = pltPtr->source[i];
        }
        if(repeat == 0){
            tempField[pltPtr->sourceNum] = *source;
            free(pltPtr->source);
            pltPtr->source = tempField;
            pltPtr->sourceNum++;
        }else
            free(tempField);
    }
}

void pltAddDest(plt *pltPtr, field *dest){
    if(pltPtr->destNum == 0){
        pltPtr->dest = (field *)malloc(sizeof(field));
        if(pltPtr->dest == NULL){
            printf("plt add source field fail!\n");
            exit(1);
        }
        *(pltPtr->dest) = *dest;
        pltPtr->destNum++;
    }else{
        field *tempField = (field *)malloc( sizeof(field) * (pltPtr->destNum+1) );
        if(tempField == NULL){
            printf("plt add source field fail!\n");
            exit(1);
        }
        int repeat = 0;
        for(int i = 0 ; i < pltPtr->destNum; i++){
            if(compare2IpSame(pltPtr->dest[i].ip, dest->ip, dest->length) && pltPtr->dest[i].length == dest->length){
                repeat = 1;
                break;
            }
            tempField[i] = pltPtr->dest[i];
        }
        if(repeat == 0){
            tempField[pltPtr->destNum] = *dest;
            free(pltPtr->dest);
            pltPtr->dest = tempField;
            pltPtr->destNum++;
        }else
            free(tempField);
    }
}

void pltRulePush(plt *pltPtr, rule *targetRule){
    if(pltPtr->ruleNum == 0){
        pltPtr->ruleList = (rule *)malloc(sizeof(rule));
        if(pltPtr->ruleList == NULL){
            printf("plt add rule fail");
            exit(1);
        }
        pltPtr->ruleList[0].source = targetRule->source;
        pltPtr->ruleList[0].destination = targetRule->destination;
        pltPtr->ruleNum++;
        pltAddSource(pltPtr, &(targetRule->source));
        pltAddDest(pltPtr, &(targetRule->destination));
        return;
    }

    rule *newRuleList = (rule *)malloc(sizeof(rule) * (pltPtr->ruleNum + 1));
    for(int i = 0 ; i < pltPtr->ruleNum; i++){
        // check if any rules in pltPtr has the same value as targetRule
        int repeatTime = 0;
        if(compare2IpSame(pltPtr->ruleList[i].source.ip, targetRule->source.ip, targetRule->source.length))
            repeatTime += 1;
        if(compare2IpSame(pltPtr->ruleList[i].destination.ip, targetRule->destination.ip, targetRule->destination.length))
            repeatTime += 1;

        if(repeatTime == 2){ // if so, do nothing
            free(newRuleList);
            return;
        }else{ // otherwise, copy values in old list to new list
            newRuleList[i] = pltPtr->ruleList[i];
        }
    }

    // add the new rule at the bottom of new rule list
    newRuleList[pltPtr->ruleNum++] = *targetRule;
    free(pltPtr->ruleList);
    
    // replace pltPtr's rule list with the new oen
    pltPtr->ruleList = newRuleList;

    // push new src and dst field
    pltAddSource(pltPtr, &(targetRule->source));
    pltAddDest(pltPtr, &(targetRule->destination));
}

plt *createPLTList(ruleTable *ruleTable){
    plt *head = createPLT();
    if(head == NULL){
        printf("create plt fail");
        exit(1);
    }

    for(int i = 0; i < ruleTable->nowRuleNum; i++){
        plt *pltPtr = head;
        int pushSuccess = 0;
        while(pltPtr->next != NULL){
            pltPtr = pltPtr->next;
            if(ruleTable->table[i].source.length == pltPtr->srcLen && 
                ruleTable->table[i].destination.length == pltPtr->dstLen){
                pltRulePush(pltPtr, &(ruleTable->table[i]));
                pushSuccess = 1;
                break;
            }
        }
        if(pushSuccess == 0){
            // printf("new plt create!\n");
            pltPtr->next = createPLT(ruleTable->nowRuleNum);
            pltPtr = pltPtr->next;
            pltPtr->srcLen = ruleTable->table[i].source.length;
            pltPtr->dstLen = ruleTable->table[i].destination.length;
            pltRulePush(pltPtr, &(ruleTable->table[i]));
        }
    }
    return head;
}

void freePLTList(plt *mainPltList){
    plt *pltPtr = mainPltList;
    while(pltPtr != NULL){
        free(pltPtr->ruleList);
        plt *previousPlt = pltPtr;
        pltPtr = pltPtr->next;
        free(previousPlt);
    }
}

void printMainPLT(ruleTable *mainRuleTable, plt *mainPlt){
    plt *pltPtr = mainPlt;
    while(pltPtr != NULL){
        printf("plt pair:T(%d, %d)    rule Number:%d\n", 
                pltPtr->srcLen, pltPtr->dstLen, pltPtr->ruleNum);
        for(int i = 0; i < pltPtr->ruleNum; i++){
            unsigned int srcIp = pltPtr->ruleList[i].source.ip;
            unsigned int dstIp = pltPtr->ruleList[i].destination.ip;
            printf("src:");
            for(int bit = 0; bit < 32; bit += 8)
                printf("%u.", (srcIp >> (24 - bit)) & 0x000000ff);
            printf(" len:%d\n", pltPtr->ruleList[i].source.length);
            printf("dst:");
            for(int bit = 0; bit < 32; bit += 8)
                printf("%u.", (dstIp >> (24 - bit)) & 0x000000ff);
            printf(" len:%d\n", pltPtr->ruleList[i].destination.length);
        }
        printf("\n");
        pltPtr = pltPtr->next;
    }
}

int **createCostMatrix(ruleTable *mainRuleTable, plt *mainPltList){
    int originPltNum = 0;
    plt *pltPtr = mainPltList;
    while(pltPtr->next != NULL){
        originPltNum++;
        pltPtr = pltPtr->next;
    }

    int **costMatrix = (int **)malloc(sizeof(int *) * originPltNum);
    if(costMatrix == NULL){
        printf("create cost matrix fail\n");
        exit(1);
    }
    for(int i = 0; i < originPltNum; i++){
        costMatrix[i] = (int *)malloc(sizeof(int) * originPltNum);
        if(costMatrix == NULL){
            printf("create cost matrix fail\n");
            exit(1);
        }        
        for(int j = 0; j < originPltNum; j++){
            costMatrix[i][j] = -1;
        }
    }
    return costMatrix;
}

int compare2IpSame(unsigned int ip1, unsigned int ip2, unsigned int compareBit){
    if(compareBit > 32 || compareBit < 0){
        printf("compare ip with illegal bit number\n");
        exit(1);
    }
    unsigned int tempIp1, tempIp2;
    unsigned int mask;
    if(compareBit == 32)
        mask = 0xffffffff;
    else if(compareBit == 0)
        mask = 0;
    else
        mask = ( (0x00000001 << compareBit) - 1) << (32 - compareBit);
    tempIp1 = mask & ip1;
    tempIp2 = mask & ip2;
    if(tempIp1 == tempIp2)
        return 1;
    else
        return 0;
}

int getFitRuleNum(ruleTable *mainRuleTable, field *srcIp, field *dstIp){
    int totalFitRuleNum = 0;
    for(int i = 0; i < mainRuleTable->nowRuleNum; i++){
        field *targetSrc = &(mainRuleTable->table[i].source);
        int srcFit = 0; // 0 means target source ip isn't the prefix of input parameter source ip 
        if(targetSrc->length <= srcIp->length){
            if(!compare2IpSame(targetSrc->ip, srcIp->ip, targetSrc->length))
                continue;
        }else
            continue;
        
        field *targetDst = &(mainRuleTable->table[i].destination);
        int dstFit = 0;
        if(targetDst->length <= dstIp->length){
            if(!compare2IpSame(targetDst->ip, dstIp->ip, targetDst->length))
                continue;
        }else
            continue;
        totalFitRuleNum++;
    }
    // printf("%d\n", totalFitRuleNum);
    return totalFitRuleNum;
}

void printFieldList(field *srcIp, int srcIpNum, field *dstIp, int dstIpNum){
    for(int i = 0; i < srcIpNum; i++){
        printf("srcIp:");
        for(int bit = 0; bit < 32; bit++){
            if(bit % 5 == 0)
                printf(" ");
            printf("%d", (srcIp[i].ip >> (31 - bit)) & 0x00000001);
        }
        printf(" len:%d\n", srcIp[i].length);
    }
}

int getRuleNum(ruleTable *mainRuleTable, plt *pltPtr){
    // list all non-repeat field in plt1 and plt2, then we can do cross product using field1 and field2
    field *plt1Src, *plt1Dst;
    
    plt1Src = createField(pltPtr->sourceNum);
    plt1Dst = createField(pltPtr->destNum);
    getNonRepeatField(pltPtr, plt1Src, plt1Dst);

    int ruleNum = 0;
    for(int i = 0 ; i < pltPtr->sourceNum; i++){
        for(int j = 0; j < pltPtr->destNum; j++){
            ruleNum += getFitRuleNum(mainRuleTable, &(plt1Src[i]), &(plt1Dst[j]));
        }
    }
    free(plt1Src);
    free(plt1Dst);
    return ruleNum;
}

void getNonRepeatField(plt *pltPtr, field *srcPtr, field *dstPtr){
    int srcListId = 0, dstListId = 0;

    for(int i = 0 ; i < pltPtr->ruleNum; i++){
        int srcRepeat = 0;
        for(int j = 0 ; j < srcListId; j++){
            if(pltPtr->ruleList[i].source.length == srcPtr[j].length &&
                compare2IpSame(pltPtr->ruleList[i].source.ip, srcPtr[j].ip, srcPtr[j].length)){
                    srcRepeat = 1;
                    break;
                }
        }
        int dstRepeat = 0;
        for(int j = 0 ; j < dstListId; j++){
            if(pltPtr->ruleList[i].destination.length == dstPtr[j].length &&
                compare2IpSame(pltPtr->ruleList[i].destination.ip, dstPtr[j].ip, dstPtr[j].length)){
                    dstRepeat = 1;
                    break;
                }
        }
        if(srcRepeat == 0)
            srcPtr[srcListId++] = pltPtr->ruleList[i].source;
        if(dstRepeat == 0)
            dstPtr[dstListId++] = pltPtr->ruleList[i].destination;
    }

} 

int getRuleNumAfterMerging(ruleTable *mainRuleTable, plt *plt1, plt *plt2){
    field *plt1Src, *plt1Dst, *plt2Src, *plt2Dst;
    
    plt1Src = createField(plt1->sourceNum);
    plt1Dst = createField(plt1->destNum);
    getNonRepeatField(plt1, plt1Src, plt1Dst);

    plt2Src = createField(plt2->sourceNum);
    plt2Dst = createField(plt2->destNum);
    getNonRepeatField(plt2, plt2Src, plt2Dst);

    int srcRepeatNum = 0;
    for(int i = 0 ; i < plt1->sourceNum; i++){
        for(int j = 0; j < plt2->sourceNum; j++){
            if(plt1Src[i].length == plt2Src[j].length && 
                compare2IpSame(plt1Src[i].ip, plt2Src[j].ip, plt1Src[i].length)){
                    srcRepeatNum++;
            }
        }
    }

    int dstRepeatNum = 0;
    for(int i = 0 ; i < plt1->destNum; i++){
        for(int j = 0; j < plt2->destNum; j++){
            if(plt1Dst[i].length == plt2Dst[j].length && 
                compare2IpSame(plt1Dst[i].ip, plt2Dst[j].ip, plt1Dst[i].length)){
                    dstRepeatNum++;
            }
        }
    }

    field *totalSrcField, *totalDstField;
    totalSrcField = (field *)malloc(sizeof(field) * (plt1->sourceNum + plt2->sourceNum - srcRepeatNum));
    totalDstField = (field *)malloc(sizeof(field) * (plt1->destNum + plt2->destNum - dstRepeatNum));
    int totalSrcId = 0, totalDstId = 0;
    for(int i = 0 ; i < plt1->sourceNum; i++){
        totalSrcField[i] = plt1Src[i];
        totalSrcId++;
    }
    for(int i = 0; i < plt2->sourceNum; i++){
        int repeat = 0;
        for(int j = 0 ; j < totalSrcId; j++){
            if(plt2Src[i].length == totalSrcField[j].length &&
                compare2IpSame(plt2Src[i].ip, totalSrcField[j].ip, plt2Src[i].length)){
                    repeat = 1;
                    break;
            }
        }
        if(repeat == 0)
            totalSrcField[totalSrcId++] = plt2Src[i];
    }

    for(int i = 0 ; i < plt1->destNum; i++){
        totalDstField[i] = plt1Dst[i];
        totalDstId++;
    }
    for(int i = 0; i < plt2->destNum; i++){
        int repeat = 0;
        for(int j = 0 ; j < totalDstId; j++){
            if(plt2Dst[i].length == totalDstField[j].length &&
                compare2IpSame(plt2Dst[i].ip, totalDstField[j].ip, plt2Dst[i].length)){
                    repeat = 1;
                    break;
            }
        }
        if(repeat == 0)
            totalDstField[totalDstId++] = plt2Dst[i];
    }

    int fitRuleNum = 0;
    for(int i = 0 ; i < totalSrcId; i++){
        for(int j = 0 ; j < totalDstId; j++){
            fitRuleNum += getFitRuleNum(mainRuleTable, &(totalSrcField[i]), &(totalDstField[j]));
        }
    }
    free(plt1Src);
    free(plt1Dst);
    free(plt2Src);
    free(plt2Dst);
    free(totalSrcField);
    free(totalDstField);
    return fitRuleNum;
}

int calCrossRuleNum(ruleTable *mainRuleTable, plt *mainPltList, int listId1, int listId2){
    // modify needed
    // the correct formula is : the total rules of merging table - the origin rules and the psuedo rules of both plts 
    plt *plt1 = NULL, *plt2 = NULL;
    int listCount = 0, fitPltNum = 0;
    plt *pltPtr = mainPltList;

    // make plt1 and plt2 point to the target plt in mainPltList
    while(pltPtr->next != NULL){
        pltPtr = pltPtr->next;
        if(listCount == listId1){
            plt1 = pltPtr;
            fitPltNum++;
        }
        if(listCount == listId2){
            plt2 = pltPtr;
            fitPltNum++;
        }
        if(fitPltNum == 2)
            break;
        listCount++;
    }
    if(plt1 == NULL || plt2 == NULL){
        printf("plt id error !!");
        exit(1);
    }
    if(plt1->ruleNum < 0 || plt2->ruleNum < 0)
        return -1;

    int mergeRuleNum = getRuleNumAfterMerging(mainRuleTable, plt1, plt2);
    int pltRuleNum1 = getRuleNum(mainRuleTable, plt1);
    int pltRuleNum2 = getRuleNum(mainRuleTable, plt2);

    return mergeRuleNum - pltRuleNum1 - pltRuleNum2;
}

void printCostMatrix(plt *mainPltList, int **costMatrix){
    // count how many plts are there in mainPltList
    int originPltNum = 0;
    plt *pltPtr = mainPltList;
    while(pltPtr->next != NULL){
        originPltNum++;
        pltPtr = pltPtr->next;
    }

    // calculate the merge cost when merging plt item [i] and [j] in mainPltList
    for(int row = 0; row < originPltNum; row++){
        for(int col = 0; col < originPltNum; col++){
            // cross rule number - origin rule num = merge cost
            printf("%3d, ", costMatrix[row][col]);
            // break;
        }
        printf("\n");
        // break;
    }
}

void calCostMatrix(ruleTable *mainRuleTable, plt *mainPltList, int **costMatrix){
    // count how many plts are there in mainPltList
    int originPltNum = 0;
    plt *pltPtr = mainPltList;
    while(pltPtr->next != NULL){
        originPltNum++;
        pltPtr = pltPtr->next;
    }

    // calculate the merge cost when merging plt item [i] and [j] in mainPltList
    for(int row = 0; row < originPltNum; row++){
        for(int col = row + 1; col < originPltNum; col++){
            // cross rule number - origin rule num = merge cost
            costMatrix[row][col] = calCrossRuleNum(mainRuleTable, mainPltList, row, col);
            // break;
        }
        // break;
    }
}

void freeMergePltCost(plt *mainPltList, int **mergePltCost){
    int originPltNum = 0;
    plt *pltPtr = mainPltList;
    while(pltPtr->next != NULL){
        originPltNum++;
        pltPtr = pltPtr->next;
    }
    for(int i = 0; i < originPltNum; i++){
        for(int j = 0; j < originPltNum; j++){
            // printf("%d ", mergePltCost[i][j]);
        }
        // printf("\n");
        free(mergePltCost[i]);
    }
}

int *findMinCoor(int pltNum, int **costMatrix){
    // find row id and column id where merge cost has minimun value
    int row = -1, column = -1;
    int minimunVal = INT_MAX;
    for(int i = 0; i < pltNum; i++){
        for(int j = i + 1; j < pltNum; j++){
            if(costMatrix[i][j] < minimunVal && costMatrix[i][j] >= 0){
                row = i;
                column = j;
                minimunVal = costMatrix[i][j];
            }
        }
    }

    int *coor = (int *)malloc(sizeof(int) * 2);
    if(coor == NULL){
        printf("find minimun value in cost matrix fail");
        exit(1);
    }
    coor[0] = row;
    coor[1] = column;
    return coor;
}

void merge2Plt(plt *mainPlts, int firstId, int secondId){
    plt *pltPtr = mainPlts;
    int pltCount = 0;

    // let plt1 and plt2 point to the certain items in mainPltList
    plt *plt1, *plt2;
    int fitCount = 0;
    while(pltPtr->next != NULL){
        pltPtr = pltPtr->next;
        if(pltCount == firstId){
            plt1 = pltPtr;
            fitCount++;    
        }
        if(pltCount == secondId){
            plt2 = pltPtr;
            fitCount++;
        }
        if(fitCount == 2)
            break;
        pltCount++;
    }

    // make sure that plt1's id is smaller than plt2's id (plt1 is closer to the head of pltList)
    if(firstId > secondId){
        plt *tempPlt = plt1;
        plt1 = plt2;
        plt2 = tempPlt;
    }

    // plt2's rule to plt1
    for(int i = 0 ; i < plt2->ruleNum; i++)
        pltRulePush(plt1, &(plt2->ruleList[i]));

    plt2->srcLen = -1;
    plt2->dstLen = -1;
    free(plt2->ruleList);
    plt2->ruleList = NULL;
    plt2->ruleNum = -1;
}

void mergePlts(ruleTable *mainTable, plt *mainPlts, int **costMatrix, int targetNum){
    plt *pltPtr = mainPlts;
    int pltNum = 0, alivePltNum = 0;
    while(pltPtr->next != NULL){
        pltPtr = pltPtr->next;
        pltNum++;
        if(pltPtr->ruleNum != -1){
            // printf("pltnum:%d\n", pltPtr->ruleNum);
            alivePltNum++;
        }
    }
    // printf("total reduce : %d\n", pltNum - targetNum);
    for(int i = 0 ; i < pltNum - targetNum; i++){
        // printf("iteration:%d\n", i);
        // find minimun row-column pair in cost martrix
        int *minimunCoor = findMinCoor(pltNum, costMatrix);
        // merge 2 plts and set one of them into unactive situation
        // printf("min coor:[%d, %d]\n", minimunCoor[0], minimunCoor[1]);
        merge2Plt(mainPlts, minimunCoor[0], minimunCoor[1]);
        // rewrite cost matrix, remember to set some of the item into -1
        calCostMatrix(mainTable, mainPlts, costMatrix);

        free(minimunCoor);
    }
}

void hashPushRule(plt *hashTable, field *srcIp, field *dstIp){
    unsigned int id = (srcIp->ip + dstIp->ip) % 13;

    rule *newRule = (rule *)malloc(sizeof(rule));
    newRule->source = *srcIp;
    newRule->destination = *dstIp;
    newRule->next = NULL;

    if(hashTable->hash[id] == NULL){
        hashTable->hash[id] = newRule;
    }else{
        rule *rulePtr = hashTable->hash[id];
        int repeatNum = 0;
        while(rulePtr->next != NULL){
            rulePtr = rulePtr->next;
            if(rulePtr->source.length == srcIp->length &&
                compare2IpSame(rulePtr->source.ip, srcIp->ip, srcIp->length)){
                repeatNum++;
            }
            if(rulePtr->destination.length == dstIp->length &&
                compare2IpSame(rulePtr->destination.ip, dstIp->ip, dstIp->length)){
                repeatNum++;
            }
            if(repeatNum == 2)
                break;
            else
                repeatNum = 0;
        }
        if(repeatNum != 2)
            rulePtr->next = newRule;
        else
            free(newRule);
    }
}

void initHashTable(ruleTable *mainRuleTable, plt *mainPlt, int id, plt *hashtable){
    int pltId = -1;
    plt *pltPtr = mainPlt;
    while(pltPtr->next != NULL){
        pltPtr = pltPtr->next;
        if(pltPtr->ruleNum != -1)
            pltId++;
        if(pltId == id)
            break;
    }

    hashtable->sourceNum = pltPtr->sourceNum;
    hashtable->source = (field *)malloc(sizeof(field) * hashtable->sourceNum);
    for(int i = 0; i < hashtable->sourceNum; i++)
        hashtable->source[i] = pltPtr->source[i];

    hashtable->destNum = pltPtr->destNum;
    hashtable->dest = (field *)malloc(sizeof(field) * hashtable->destNum);
    for(int i = 0; i < hashtable->destNum; i++)
        hashtable->dest[i] = pltPtr->dest[i];

    hashtable->hash = (rule **)malloc(sizeof(rule *) * 13);
    if(hashtable->hash == NULL){
        printf("create hash array fail");
        exit(1);
    }
    for(int i = 0 ; i < 13; i++)
        hashtable->hash[i] = NULL;

    for(int i = 0; i < hashtable->sourceNum; i++){
        for(int j = 0; j < hashtable->destNum; j++){
            if(getFitRuleNum(mainRuleTable, &(hashtable->source[i]), &(hashtable->dest[j])) > 0)
                hashPushRule(hashtable, &(hashtable->source[i]), &(hashtable->dest[j]));
        }
    }
}

plt *createFinalTable(ruleTable *mainRuleTable, plt *mainPlt){
    int alivePltNum = 0;
    plt *pltPtr = mainPlt;

    while(pltPtr->next != NULL){
        pltPtr = pltPtr->next;
        if(pltPtr->ruleNum != -1)
            alivePltNum++;
    }

    plt *hashPltList = (plt *)malloc(sizeof(plt) * alivePltNum);
    if(hashPltList == NULL){
        printf("create hash table list fail");
        exit(1);
    }

    for(int i = 0 ; i < alivePltNum; i++){
        initHashTable(mainRuleTable, mainPlt, i, &(hashPltList[i]));
    }
    return hashPltList;
}

void freeHashPltList(plt *mainPlt, plt *hashList){
    int alivePltNum = 0;
    plt *pltPtr = mainPlt;

    while(pltPtr->next != NULL){
        pltPtr = pltPtr->next;
        if(pltPtr->ruleNum != -1)
            alivePltNum++;
    }

    for(int i = 0; i < alivePltNum; i++){
        // printf("hash table:%d\n", i);
        free(hashList[i].source);
        free(hashList[i].dest);
        for(int j = 0; j < 13; j++){
            // printf("hash list:%d\n", j);
            rule *rulePtr = hashList[i].hash[j];
            rule *prevRule;
            while (rulePtr != NULL){
                prevRule = rulePtr;
                rulePtr = rulePtr->next;
                // printf("addr:%d\n", prevRule);
                // printf("src ip:%d  len:%d\n", prevRule->source.ip, prevRule->source.length);
                // printf("dst ip:%d  len:%d\n", prevRule->destination.ip, prevRule->destination.length);
                free(prevRule);
            }
        }
        // printf("\n\n\n", i);
        free(hashList[i].hash);
    }
    free(hashList);
}

typedef struct{
    int *inHashTable;
    field data;
} oneDimField;

int getTableSrcNum(ruleTable *mainRuleTable){
    int totalNum = 0;
    field *fieldHead = NULL;
    field *fieldPtr;
    // printf("1-1\n");
    for(int i = 0; i < mainRuleTable->nowRuleNum; i++){
        // printf("no.%d rule\n", i);
        field *targetSrc = &(mainRuleTable->table[i].source);
        fieldPtr = fieldHead;
        if(fieldPtr == NULL){
            fieldHead = createField(1);
            *fieldHead = *targetSrc;
            fieldHead->next = NULL;
            totalNum++;
            continue;
        }
        // printf("1-2\n");
        int repeat = 0;
        field *prev;
        while(fieldPtr != NULL){
            if(fieldPtr->length == targetSrc->length &&
                compare2IpSame(fieldPtr->ip, targetSrc->ip, (int)(targetSrc->length))){
                repeat = 1;
                break;
            }
            prev = fieldPtr;
            fieldPtr = fieldPtr->next;
        }
        // printf("addr:%u  ip:%u  len:%u\n", prev, prev->ip, prev->length);
        if(repeat != 1){
            field *temp = createField(1);
            *temp = *targetSrc;
            temp->next = NULL;
            prev->next = temp;
            totalNum++;
        }
    }
    fieldPtr = fieldHead;
    field *nextPtr;
    while(fieldPtr != NULL){
        nextPtr = fieldPtr->next;
        free(fieldPtr);
        fieldPtr = nextPtr;
    }
    return totalNum;
}

int getTableDstNum(ruleTable *mainRuleTable){
    int totalNum = 0;
    field *fieldHead = NULL;
    field *fieldPtr;
    for(int i = 0; i < mainRuleTable->nowRuleNum; i++){
        fieldPtr = fieldHead;
        field targetDst = mainRuleTable->table[i].destination;
        if(fieldPtr == NULL){
            fieldHead = createField(1);
            *fieldHead = targetDst;
            totalNum++;
            continue;
        }

        int repeat = 0;
        field *prev;
        while(fieldPtr != NULL){
            if(fieldPtr->length == targetDst.length &&
                compare2IpSame(fieldPtr->ip, targetDst.ip, targetDst.length)){
                repeat = 1;
                break;
            }
            prev = fieldPtr;
            fieldPtr = fieldPtr->next;
        }
        if(repeat != 1){
            field *temp = createField(1);
            *temp = targetDst;
            prev->next = temp;
            totalNum++;
        }
    }
    fieldPtr = fieldHead;
    field *nextPtr;
    while(fieldPtr != NULL){
        nextPtr = fieldPtr->next;
        free(fieldPtr);
        fieldPtr = nextPtr;
    }
    return totalNum;
}

void fillFieldData(ruleTable *mainRuleTable, oneDimField **fieldTable){
    // fill data into src (fieldTable[0])
    int srcId = 0;
    for(int i = 0; i < mainRuleTable->nowRuleNum; i++){
        field *tempSrc = &(mainRuleTable->table[i].source);
        int repeat = 0;
        for(int j = 0; j < srcId; j++){
            if(fieldTable[0][j].data.length == tempSrc->length &&
                compare2IpSame(fieldTable[0][j].data.ip, tempSrc->ip, tempSrc->length)){
                    repeat = 1;
                    break;
            }
        }
        if(repeat == 0)
            fieldTable[0][srcId++].data = *tempSrc;
    }

    // fill data into dst (fieldTable[1])
    int dstId = 0;
    for(int i = 0; i < mainRuleTable->nowRuleNum; i++){
        field *tempDst = &(mainRuleTable->table[i].destination);
        int repeat = 0;
        for(int j = 0; j < dstId; j++){
            if(fieldTable[1][j].data.length == tempDst->length &&
                compare2IpSame(fieldTable[1][j].data.ip, tempDst->ip, tempDst->length)){
                    repeat = 1;
                    break;
            }
        }
        if(repeat == 0)
            fieldTable[1][dstId++].data = *tempDst;
    }
}

int srcInPlt(field *data, plt *hashPlt){
    for(int i = 0; i < hashPlt->sourceNum; i++){
        if(data->length == hashPlt->source[i].length && data->ip == hashPlt->source[i].ip)
            return 1;
    }
    return 0;
}

int dstInPlt(field *data, plt *hashPlt){
    for(int i = 0; i < hashPlt->destNum; i++){
        if(data->length == hashPlt->dest[i].length && data->ip == hashPlt->dest[i].ip)
            return 1;
    }
    return 0;
}

void fillHashTable(plt *hashPltList, oneDimField **fieldTable, int pltNum, int srcNum, int dstNum){
    for(int i = 0; i < srcNum; i++){
        fieldTable[0][i].inHashTable = (int *)malloc(sizeof(int) * pltNum);
        if(fieldTable[0][i].inHashTable == NULL){
            printf("create hash table in 1-d field table fail");
            exit(1);
        }
        for(int j = 0; j < pltNum; j++){
            fieldTable[0][i].inHashTable[j] = srcInPlt(&(fieldTable[0][i].data), &(hashPltList[j]));
        }
    }
    for(int i = 0; i < dstNum; i++){
        fieldTable[1][i].inHashTable = (int *)malloc(sizeof(int) * pltNum);
        if(fieldTable[1][i].inHashTable == NULL){
            printf("create hash table in 1-d field table fail");
            exit(1);
        }
        for(int j = 0; j < pltNum; j++){
            fieldTable[1][i].inHashTable[j] = dstInPlt(&(fieldTable[1][i].data), &(hashPltList[j]));
        }
    }
}

oneDimField **createFieldTableList(ruleTable *mainRuleTable, plt *hashPltList, int pltNum){
    oneDimField **fieldTable = (oneDimField **)malloc(sizeof(oneDimField *) * 2);
    if(fieldTable == NULL){
        printf("create 1-d field table fail");
        exit(1);
    }

    int srcNum = getTableSrcNum(mainRuleTable);
    int dstNum = getTableDstNum(mainRuleTable);
    // printf("src number:%d\n", srcNum);
    // printf("dst number:%d\n", dstNum);

    fieldTable[0] = (oneDimField *)malloc(sizeof(oneDimField) * srcNum);
    fieldTable[1] = (oneDimField *)malloc(sizeof(oneDimField) * dstNum);

    fillFieldData(mainRuleTable, fieldTable);
    fillHashTable(hashPltList, fieldTable, pltNum, srcNum, dstNum);
    return fieldTable;
}

void printFieldTable(ruleTable *mainRuleTable, oneDimField **fieldList, plt *hashPltList, int pltNum){
    int srcNum = getTableSrcNum(mainRuleTable);
    int dstNum = getTableDstNum(mainRuleTable);
    printf("src number:%d\n", srcNum);
    printf("dst number:%d\n", dstNum);

    for(int i = 0; i < srcNum; i++){
        printf("field list[0][%d]:", i);
        printf("src ip:%u len:%u    ", fieldList[0][i].data.ip, fieldList[0][i].data.length);
        printf("hash table [%d, %d, %d, %d, %d, %d]\n", 
                fieldList[0][i].inHashTable[0], 
                fieldList[0][i].inHashTable[1], 
                fieldList[0][i].inHashTable[2], 
                fieldList[0][i].inHashTable[3], 
                fieldList[0][i].inHashTable[4], 
                fieldList[0][i].inHashTable[5]);
    }

    printf("\n\n");

    for(int i = 0; i < dstNum; i++){
        printf("field list[0][%d]:", i);
        printf("dst ip:%u len:%u    ", fieldList[1][i].data.ip, fieldList[1][i].data.length);
        printf("hash table [%d, %d, %d, %d, %d, %d]\n", 
                fieldList[1][i].inHashTable[0], 
                fieldList[1][i].inHashTable[1], 
                fieldList[1][i].inHashTable[2], 
                fieldList[1][i].inHashTable[3], 
                fieldList[1][i].inHashTable[4], 
                fieldList[1][i].inHashTable[5]);
    }
}

void freeOneDimField(ruleTable *mainRuleTable, oneDimField **fieldTable, int targetPltNum){
    int srcNum = getTableSrcNum(mainRuleTable);
    int dstNum = getTableDstNum(mainRuleTable);
    for(int i = 0; i < srcNum; i++)
        free(fieldTable[0][i].inHashTable);
    for(int i = 0; i < dstNum; i++)
        free(fieldTable[1][i].inHashTable);
    free(fieldTable);
}

int checkSamePlt(int *srcHash, int *dstHash, int pltNum){
    for(int i = 0; i < pltNum; i++){
        if(srcHash[i] == 1 && dstHash[i] == 1)
            return i;
    }
    return -1;
}

void getRule(field *tempSrc, field *tempDst, plt *hashPltList, int pltId){
    int hashId = (tempSrc->ip + tempDst->ip) % 13;
    rule *tempRule = hashPltList[pltId].hash[hashId];
    while (tempRule != NULL){
        field *targetSrc, *targetDst;
        targetSrc = &(tempRule->source);
        targetDst = &(tempRule->destination);
        int sameSrc = 0, sameDst = 0;
        if(targetSrc->length == tempSrc->length && targetSrc->ip == tempSrc->ip)
            sameSrc = 1;
        if(targetDst->length == tempDst->length && targetDst->ip == tempDst->ip)
            sameDst = 1;
        if(sameSrc == 1 && sameDst == 1)
            break;
        tempRule = tempRule->next;
    }
}

void getIpInFieldList(field *targetSrc, field *targetDst, oneDimField **fieldTableList,
                        plt *hashPltList, int srcNum, int dstNum, int pltNum){
    for(int i = 0; i < srcNum; i++){
        for(int j = 0; j < dstNum; j++){
            field *tempSrc = &(fieldTableList[0][i].data);
            field *tempDst = &(fieldTableList[1][j].data);
            
            int srcFit = 0, dstFit = 0;
            if(compare2IpSame(targetSrc->ip, tempSrc->ip, tempSrc->length))
                srcFit = 1;
            if(compare2IpSame(targetDst->ip, tempDst->ip, tempDst->length))
                dstFit = 1;

            int *srcHash, *dstHash;
            if(srcFit == 1 && dstFit == 1){
                srcHash = fieldTableList[0][i].inHashTable;
                dstHash = fieldTableList[1][j].inHashTable;
                int pltId = checkSamePlt(srcHash, dstHash, pltNum);
                if(pltId != -1){
                    getRule(tempSrc, tempDst, hashPltList, pltId);
                    printf("success\n");
                    return;
                }
            }
        }
    }
    printf("fail\n");
}

void readQueryRule(ruleTable *mainRuleTable, char *inPath, 
                    oneDimField **fieldTableList, plt *hashPltList, int targetPltNum){
    // Open the input file in read mode
    FILE *file = fopen(inPath, "r");
    if (file == NULL) {
        perror("Error opening file");
        exit(1);
    }

    // Buffer to hold each line
    char line[MAX_LINE_LENGTH];
    int srcNum = getTableSrcNum(mainRuleTable);
    int dstNum = getTableDstNum(mainRuleTable);

    // Read each line from the file
    while(fgets(line, sizeof(line), file)){
        char src_ip[20], dst_ip[20], src_port_range[20], dst_port_range[20], protocol[20], flags[20];

        // Parse the line and store the values into respective variables
        if (sscanf(line, "%s %s %s %s %s %s",
                   src_ip, dst_ip, src_port_range, dst_port_range, protocol, flags) == 6) {
            // Print the parsed data
        } else {
            fprintf(stderr, "Error parsing line: %s\n", line);
        }

        field targetSrc, targetDst;
        targetSrc.ip = atoi(src_ip);
        targetSrc.length = 32;
        targetSrc.next = NULL;
        targetDst.ip = atoi(dst_ip);
        targetDst.length = 32;
        targetDst.next = NULL;
        printf("src ip:");
        for(int bit = 0; bit < 32; bit += 8)
            printf("%u.", (targetSrc.ip >> (24 - bit)) & 0x000000ff);
        printf(" len:%u\n", targetSrc.length);
        printf("dst ip:");
        for(int bit = 0; bit < 32; bit += 8)
            printf("%u.", (targetDst.ip >> (24 - bit)) & 0x000000ff);
        printf(" len:%u\n", targetDst.length);
        getIpInFieldList(&targetSrc, &targetDst, fieldTableList, hashPltList, srcNum, dstNum, targetPltNum);

    }
    // Close the file
    fclose(file);
}

void printHashPLT(plt *hashPltList, int targetPltNum){
    for(int i = 0; i < targetPltNum; i++){
        printf("plt:%d\n", i);
        plt *pltPtr = &(hashPltList[i]); 
        for(int seg = 0; seg < 13; seg++){
            rule *rulePtr = pltPtr->hash[seg];
            while(rulePtr != NULL){
                printf("src ip: ");    
                for(int bit = 0; bit < 32; bit += 8)
                    printf("%u.", (rulePtr->source.ip >> (24 - bit)) & 0x000000ff);
                printf("\n");
                printf("dst ip: ");    
                for(int bit = 0; bit < 32; bit += 8)
                    printf("%u.", (rulePtr->destination.ip >> (24 - bit)) & 0x000000ff);
                rulePtr = rulePtr->next;
                printf("\n");
            }
        }
    }
}

int main(){
    // read packet for building classification rules
    char *inPath = "acl1_1k copy";
    ruleTable *mainRuleTable = createRuleTable(100);
    readInRule(inPath, mainRuleTable);
    // printRuleTable(mainRuleTable);

    // split classification rules into different plts(prefix-length tuple)
    plt *mainPlt = createPLTList(mainRuleTable);
    // printMainPLT(mainRuleTable, mainPlt);

    // create a empty matrix for recording merge cost between
    int **mergePltCost = createCostMatrix(mainRuleTable, mainPlt);
    calCostMatrix(mainRuleTable, mainPlt, mergePltCost);
    // printCostMatrix(mainPlt, mergePltCost);

    // merge plts until there are only targetPltNum plts in mainPltList
    int targetPltNum = 6;
    mergePlts(mainRuleTable, mainPlt, mergePltCost, targetPltNum);
    // printMainPLT(mainRuleTable, mainPlt);
    // printCostMatrix(mainPlt, mergePltCost);

    // create the hash table for query according to the information in mainPlt
    plt *hashPltList = createFinalTable(mainRuleTable, mainPlt);
    // printHashPLT(hashPltList, targetPltNum);

    // build 1-field table
    oneDimField **fieldTableList = createFieldTableList(mainRuleTable, hashPltList, targetPltNum);
    // printFieldTable(mainRuleTable, fieldTableList, hashPltList, targetPltNum);

    // // read data for examing query time
    char *tracePath = "acl1_1k_trace";
    readQueryRule(mainRuleTable, tracePath, fieldTableList, hashPltList, targetPltNum);



    freeOneDimField(mainRuleTable, fieldTableList, targetPltNum);
    freeHashPltList(mainPlt, hashPltList);
    freeMergePltCost(mainPlt, mergePltCost);
    freeRuleTable(mainRuleTable);
    freePLTList(mainPlt);
    return 0;
}