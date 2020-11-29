#include<stdio.h>	//For standard things
#include<stdlib.h>	//malloc
#include<string.h>	//memset
#include<netinet/ip_icmp.h>	//Provides declarations for icmp header
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip header
#include<sys/socket.h>
#include<arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>	//sifreq
#include <unistd.h>	//close
#include <limits.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include </home/mszostu/msgbuf.h>
#include <stdbool.h>

#define BUF_SIZE 8400
#define SHM_KEY 0x1234
#define SIZE 1024

struct shmseg {
   int cnt;
   int complete;
   char buffer[BUF_SIZE];
};

//typedef struct {

//	char *id;
//	char *data;

//}packet;


struct packet {
	// arr_packet
	int id[1];
	int data[1024];
	// packet
	char destinationIP[1024];
	char sourceIP[1024];
};

void ProcessPacket(unsigned char* , int);
void print_ip_header(unsigned char* , int);
void print_tcp_packet(unsigned char* , int);
void print_udp_packet(unsigned char * , int);
void print_icmp_packet(unsigned char* , int);
void PrintData (unsigned char* , int);

int sock_raw;
int sharedMemoryIDs[1024];
FILE *logfile;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;
struct sockaddr_in source,dest;

int itemsQ1[SIZE], frontQ1 = -1, rearQ1 = -1;
int itemsQ2[SIZE], frontQ2 = -1, rearQ2 = -1;
int itemsQ3[SIZE], frontQ3 = -1, rearQ3 = -1;

int main()
{
	int saddr_size , data_size;
	struct sockaddr saddr;
	struct in_addr in;
	
	unsigned char *buffer = (unsigned char *)malloc(65536); 
	
	logfile=fopen("/home/mszostu/altput.txt","w");
	if(logfile==NULL) printf("Unable to create file.");
	printf("Starting...\n");
	//Create a raw socket that shall sniff
	sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_ICMP);
	
	if(sock_raw < 0)
	{
		printf("Socket Error\n");
		return 1;
	}
	while(1)
	{
		saddr_size = sizeof saddr;

		data_size = recvfrom(sock_raw , buffer , 1024 , 0 , &saddr , &saddr_size);
		if(data_size <0 )
		{
			printf("Recvfrom error , failed to get packets\n");
			return 1;
		}
		tablicaKlas(buffer, data_size);
		ProcessPacket(buffer , data_size);
	  //enQueue 3 elements
 
	} 

	close(sock_raw);
	printf("Finished");
	return 0;
}
// enqueue
void enQueue(int value) {
  if (rearQ1 == SIZE - 1)
    printf("\nQueue is Full!!");
  else {
    if (frontQ1 == -1)
      frontQ1 = 0;
    rearQ1++;
    itemsQ1[rearQ1] = value;
   // printf("\nInserted -> %d", value);
	
  }
}
// dequeue
void deQueue() {
  if (frontQ1 == -1)
    printf("");
  else {
    printf("\nDequeued : %d", itemsQ1[frontQ1]);
		// write converted data to a sending buffer
	//
    frontQ1++;
    if (frontQ1 > rearQ1)
      frontQ1 = rearQ1 = -1;
  }
}

// enqueue2
void enQueue2(int value) {
  if (rearQ2 == SIZE - 1)
    printf("\nQueue is Full!!");
  else {
    if (frontQ2 == -1)
      frontQ2 = 0;
    rearQ2++;
    itemsQ2[rearQ2] = value;
   // printf("\nInserted -> %d", value);
	
  }
}
// dequeue2
void deQueue2() {
  if (frontQ2 == -1)
    printf("");
  else {
    printf("\nDequeued : %d", itemsQ2[frontQ2]);
    frontQ2++;
    if (frontQ2 > rearQ2)
      frontQ2 = rearQ2 = -1;
  }
}
// enqueue3
void enQueue3(int value) {
  if (rearQ3 == SIZE - 1)
    printf("\nQueue is Full!!");
  else {
    if (frontQ3 == -1)
      frontQ3 = 0;
    rearQ3++;
    itemsQ3[rearQ3] = value;
   // printf("\nInserted -> %d", value);
	
  }
}
// dequeue3
void deQueue3() {
  if (frontQ3 == -1)
    printf("");
  else {
    printf("\nDequeued : %d", itemsQ3[frontQ3]);
    frontQ3++;
    if (frontQ3 > rearQ3)
      frontQ3 = rearQ3 = -1;
  }
}
// Function to print the queue
void display() {
  if (rearQ1 == -1)
    printf("");
  else {
    int i;
    printf("\nQueued elements in queue 1 are:\n");
    for (i = frontQ1; i <= rearQ1; i++)
      printf("%d  ", itemsQ1[i]);
	  int numberOfElementsInQueue1 = i;
	 // printf("\nNumber of elements in Queue 1 equals: %d", numberOfElementsInQueue1);
  }
  printf("\n");
}
void display2() {
  if (rearQ2 == -1)
    printf("");
  else {
    int i;
    printf("\nQueued elements in queue 2 are:\n");
    for (i = frontQ2; i <= rearQ2; i++)
      printf("%d  ", itemsQ2[i]);
	  int numberOfElementsInQueue2 = i;
	//  printf("\nNumber of elements in Queue 2 equals: %d", numberOfElementsInQueue2);
  }
  printf("\n");
}
void display3() {
  if (rearQ3 == -1)
    printf("");
  else {
    int i;
    printf("\nQueued elements in queue 3 are:\n");
    for (i = frontQ3; i <= rearQ3; i++)
      printf("%d  ", itemsQ3[i]);
	  int numberOfElementsInQueue3 = i;
	 // printf("\nNumber of elements in Queue 3 equals: %d", numberOfElementsInQueue3); 
  }
  printf("\n");
}
void ProcessPacket(unsigned char* Buffer, int Size)
{
	// generacja wskaznika iph
	struct iphdr *iph = (struct iphdr*)Buffer;
	++total;
	switch (iph->protocol) //Check the Protocol and do accordingly...
	{
		case 1:  //ICMP Protocol
			++icmp;
			//PrintIcmpPacket(Buffer,Size);
			//checkIncomingPackets();
			print_icmp_packet(Buffer, Size);

		
		default: //Some Other Protocol like ARP etc.
			++others;
			break;
	}
}


void print_ip_header(unsigned char* Buffer, int Size)
{
	unsigned short iphdrlen;
	unsigned char tosbits;
	
	struct iphdr *iph = (struct iphdr *)Buffer;
	iphdrlen =iph->ihl*4;
	
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;


	tosbits = iph->tos;
	fprintf(logfile,"\n");
	fprintf(logfile,"IP Header\n");
	fprintf(logfile,"   |-IP Version        : %d\n",(unsigned int)iph->version);
	fprintf(logfile,"   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
	fprintf(logfile,"   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
	fprintf(logfile,"   |-The ToS bits are [DSCP]  : %d\n",tosbits);
	fprintf(logfile,"   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
	fprintf(logfile,"   |-Identification    : %d\n",ntohs(iph->id));

	fprintf(logfile,"   |-TTL      : %d\n",(unsigned int)iph->ttl);
	fprintf(logfile,"   |-Protocol : %d\n",(unsigned int)iph->protocol);
	fprintf(logfile,"   |-Checksum : %d\n",ntohs(iph->check));
	fprintf(logfile,"   |-Source IP             : %s\n",inet_ntoa(source.sin_addr));
	fprintf(logfile,"   |-Destination IP        : %s\n",inet_ntoa(dest.sin_addr));


}

void print_icmp_packet(unsigned char* Buffer , int Size)
{

	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)Buffer;
	iphdrlen = iph->ihl*4;
	
	struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen);
			
	fprintf(logfile,"\n\n***********************ICMP Packet*************************\n");	
	
	print_ip_header(Buffer , Size);
			
	fprintf(logfile,"\n");
		

	print_icmp_packet_address(Buffer, Size);
	packetNumber();
	fprintf(logfile,"\n###########################################################");
}

void PrintDataIcmp (unsigned char* data , int Size)
{
			int counter = 1;
	for(i=0 ; i < Size ; i++)

	{

		if( i!=0 && i%16==0)   //if one line of hex printing is complete...
		{
			fprintf(logfile,"         ");
			for(j=i-16 ; j<i ; j++)
			{
				if(data[j]>=32 && data[j]<=128) {
					fprintf(logfile,"%c",(unsigned char)data[j]); //if its a number or alphabet
				}

				
				else fprintf(logfile,"."); //otherwise print a dot
			}
			    

			fprintf(logfile,"\n");
		} 
		
		if(i%16==0) fprintf(logfile,"   ");
			fprintf(logfile," %02X",(unsigned int)data[i]);


		if(counter == Size) { // which byte is DSCP
		// dscp
	
		//fprintf(logfile,"[DSCP: 0x%02X]",(unsigned int)data[i+1]); // break przed samym polem DSCP
		int nval = (unsigned int)data[1];
		fprintf(logfile,"\nDSCP field: 0x0%d\n", nval);
		//break; // break przed samym polem DSCP
		
		//	
		}

		
		if( i==Size-1)  //print the last spaces
		{
			for(j=0;j<15-i%16;j++) fprintf(logfile,"   "); //extra spaces
			
			fprintf(logfile,"         ");
			
			for(j=i-i%16 ; j<=i ; j++)
			{
				if(data[j]>=32 && data[j]<=128) fprintf(logfile,"%c",(unsigned char)data[j]);
				
				else fprintf(logfile,".");
			}
			fprintf(logfile,"\n");
		}
	counter++;
	int counter = counter - 82;
	//fprintf(logfile,"\nDSCP field: 0x0%d", nval);
	}


}


void PrintData (unsigned char* data , int Size)
{
	
	for(i=0 ; i < Size ; i++)
	{
		if( i!=0 && i%16==0)   //if one line of hex printing is complete...
		{
			fprintf(logfile,"         ");
			for(j=i-16 ; j<i ; j++)
			{
				if(data[j]>=32 && data[j]<=128)
					fprintf(logfile,"%c",(unsigned char)data[j]); //if its a number or alphabet
				
				else fprintf(logfile,"."); //otherwise print a dot
			}
			fprintf(logfile,"\n");
		} 
		
		if(i%16==0) fprintf(logfile,"   ");
			fprintf(logfile," %02X",(unsigned int)data[i]);
				
		if( i==Size-1)  //print the last spaces
		{
			for(j=0;j<15-i%16;j++) fprintf(logfile,"   "); //extra spaces
			
			fprintf(logfile,"         ");
			
			for(j=i-i%16 ; j<=i ; j++)
			{
				if(data[j]>=32 && data[j]<=128) fprintf(logfile,"%c",(unsigned char)data[j]);
				else fprintf(logfile,".");
			}
			fprintf(logfile,"\n");
		}

	}
	unsigned short iphdrlen;
	unsigned char tosbits;


}

int cntQ1 = 0;
int cntQ2 = 0;
int cntQ3 = 0;

int packet_counter = -1;
int key = 0x1234;
void print_icmp_packet_address(unsigned char* Buffer , int Size) {
	struct packet arr_packet[1024]; // 1024 pakekiey, kazdy z nich ma membery 2: id oraz data (czyli dane)
	struct packet packet;

	int i; 
    int addressesMatrixForSharedMemory[1][BUF_SIZE];
	int segment_id;
	unsigned char tosbits;	
	struct iphdr *iph = (struct iphdr *)Buffer;
	tosbits = iph->tos;
    int bytes[Size]; // size of packet + 1

	//for (m =1; m< 5; m++) {
  	for (i =0; i<Size; i++) {
	 //fprintf(logfile, "Buffer array element number: %d", i)	
	 fprintf(logfile, "\n");
	 fprintf (logfile,"Buffer arr element no: %d \n", i);	  
     fprintf(logfile,"Virtual memory address: %p\n", &Buffer[i]);
     char *b;
     b = &Buffer[i];
	 //fprintf(logfile, "\n");
	 fprintf(logfile, "Value stored at virtual memory address %p is %d [in DEC] ", b, *b);
	 fprintf(logfile, "\n");
     //fprintf(logfile, "This is BUFF: %s",b); // string literal, not a variable error fix
     printf("\n");

	 ////////////////////// writing /////////////////////

	char * shared_memory;
	int segment_size;
	const int shared_segment_size = BUF_SIZE;

	/* Allocate a shared memory segment.  */
	segment_id = shmget (key, shared_segment_size, IPC_CREAT );
	/* Attach the shared memory segment.  */
	printf("Shared memory segment ID is %d\n", segment_id);
	shared_memory = (char*) shmat (segment_id, 0, 0);
	/* Write a string to the shared memory segment.  */
	sprintf (shared_memory, b);
	// reading from shared memory segment (address)
	printf("Value stored at shared memory address %p is %d\n", shared_memory, *b);
    // zebranie wartosci to tablicy jednowymiarowej bytes
    bytes[i] = *b;
    //addressesMatrixForSharedMemory [i] = *b;
    printf("Shared memory address at which the value: %d [in DEC] is being stored is: %p\n", *b, shared_memory);
	// reading from shared memory segment (based on key)
	//printf("Value stored at shared memory unique key %d is %d\n", key ,*b);
    // reading 1 byte from shared memory having segment ID and unique key to it
	printf("Shared memory key %d is permanently combined with segment ID %d\n", key ,segment_id);
	// reading class of service from the packet
	printf("Class of service is: %d for the packet in segment %d\n", tosbits, segment_id);
    int byteNo = i+1;
    printf("Byte no: %d in segment: %d", i+1, segment_id);
	/* Detach the shared memory segment.  */
	//shmdt (shared_memory);
	printf("\nWrote buffer content to the segment\n");
    if (byteNo == Size){
        key++;
		packet_counter++;
    }
	printf("packet counter is %d\n", packet_counter +1);
	sharedMemoryIDs[packet_counter] = segment_id;
	}
	printf("\nRead bytes from member 'data' of the nth element of the array:...\n");
	for (int i =0; i<Size; i++) {
		 arr_packet[packet_counter+1].data[i] = bytes[i];
		 arr_packet[packet_counter+1].id[0] = segment_id;
		 strcpy (packet.destinationIP, inet_ntoa(dest.sin_addr));
		 strcpy (packet.sourceIP, inet_ntoa(source.sin_addr));
		 printf("%d ", arr_packet[packet_counter+1].data[i]);
		 //printf("%s ", packet.destinationIP);

    }
	printf("\nRead from 'id' member of the nth element of the array : \n%d ", arr_packet[packet_counter+1].id[0]);


	// convert data from DEC to HEX
	printf("\nRead bytes from member 'data' of the nth element of the array after convertion DEC to HEX:...\n");
	int valueToConvert;
	char dataToConvert[1024];
	/// alokacja takiego bufora do wysylania pakietow
	char* bufferToSend;
	bufferToSend = (char*)malloc(1024); 
	
	for (int i =0; i<Size; i++) {
		 valueToConvert = arr_packet[packet_counter+1].data[i];
		 sprintf(dataToConvert, "%x" , valueToConvert);
		 printf("\nData after conversion: %s ", dataToConvert);
    }


	printf("\nsharedMemoryIDs[%d]: %d\n",packet_counter, sharedMemoryIDs[packet_counter]);

	if (tosbits == 1) {
	enQueue(sharedMemoryIDs[packet_counter]);
    cntQ1++;
	display();
	} else if (tosbits == 2 ) {
	enQueue2(sharedMemoryIDs[packet_counter]);	
    cntQ2++;
	display2();
	} else {
	enQueue3(sharedMemoryIDs[packet_counter]);
    cntQ3++;	
	display3();
	}

    int granularity = 5; // co ile pakietow dekolejkowanie
	//mechanizm ktora kolejka ma byc obsluzona pierwsza
	// najpierw pakiety z class = 1 wyciagane z kolejki
	// potem pakiety z klasa 2 wyciagane z kolejki
	if (packet_counter + 1 == granularity) { // jak juz wszystkie pakiety przeslane



	if (frontQ1 != -1) { // jesli jest cos w kolejce z class = 1 to najpierw z tej sciagamy pakiety
	
	  for (int sizeOfItemsQueue1 =0 ; sizeOfItemsQueue1<cntQ1; sizeOfItemsQueue1++) {  
		printf("\nSegment id of a packet that is being wriiten to a sendBuffer: %d",itemsQ1[frontQ1]);
		// write to a buffer the data from dequeued segmend ID
		for (int i = 0; i< granularity; i++){
			if (itemsQ1[frontQ1] == packet.id) {
				memcpy(bufferToSend, (char*)&dataToConvert,sizeof(int));
			}
		}
        deQueue();


	  	display();
	  } // koniec sciagania z class 1
	


	if (frontQ2 != -1) { // jesli jest cos w kolejce class 2 to z niej
	  		for (int sizeOfItemsQueue2 =0 ; sizeOfItemsQueue2 < cntQ2; sizeOfItemsQueue2++) {  
				deQueue2();
	  			display2();
	 		 } // koniec sciagania z class 2

	  		if (frontQ3 != -1) { // jesli jest cos w class 3 to z niej
	 		 for (int sizeOfItemsQueue3 =0 ; sizeOfItemsQueue3<cntQ3; sizeOfItemsQueue3++) {  
				deQueue3();
	  			display3();
	  		} // koniec sciagania z class 3
	  		} else {}

	} else if (frontQ2 == -1) { // jesli nic nie ma class 2
	  	if (frontQ3 != -1) { // jesli jest cos w class 3 to z niej
	  for (int sizeOfItemsQueue3 =0 ; sizeOfItemsQueue3<cntQ3; sizeOfItemsQueue3++) {  
		deQueue3();
	  	display3();
	  } // koniec sciagania z class 3
	  } else {}
	}


	} else if (frontQ1 == -1) { // jesli nie ma nic w kolejce z class 1
	 	 if (frontQ2 != -1) { // jesli jest cos w kolejce class 2 to z niej
	  		for (int sizeOfItemsQueue2 =0 ; sizeOfItemsQueue2<cntQ2; sizeOfItemsQueue2++) {  
				deQueue2();
	  			display2();
	 		 } // koniec sciagania z class 2
            if (frontQ3 != -1) { // jesli jest cos w class 3 to z niej
	 		 for (int sizeOfItemsQueue3 =0 ; sizeOfItemsQueue3<cntQ3; sizeOfItemsQueue3++) {  
				deQueue3();
	  			display3();
	  		} // koniec sciagania z class 3
	  		} else {}

	 	 } else if (frontQ2 == -1) { // jesli nic nie ma class 2
	  	if (frontQ3 != -1) { // jesli jest cos w class 3 to z niej
	  for (int sizeOfItemsQueue3 =0 ; sizeOfItemsQueue3<cntQ3; sizeOfItemsQueue3++) {  
		deQueue3();

       // showDequeuedPacketinfo(Buffer, Size);
	  	display3();
	  } // koniec sciagania z class 3
	  } else {}
	}

	
	
	}

    packet_counter = packet_counter - granularity;
	}



    struct shmid_ds shm_desc;
    /* destroy the shared memory segment. */
    if (shmctl(segment_id, IPC_RMID, &shm_desc) == -1) {
        perror("main: shmctl: ");

    }

}

int icmpPacketCounter = 1;
void packetNumber ()
{
		fprintf (logfile,"Packet no: %d \n", icmpPacketCounter);
		icmpPacketCounter++;
	//	int counter = 1;

}
void incremento(int *n){
  (*n)++;
}

	int liczbaPolaczen = 10; //na razie z gory ustalone 10, potem z GTK zaciagane

	int liczbaPortowWyjsciowych = 10; // narazie z gory ustalone 10, potem z GTK zaciagane

	int liczbaKlas = 5; // narazie z gory ustalone 10, potem z GTK zaciagane

	int ostatniaKartaOdczyt; // zawiera infomacje o tym, z ktorej karty wzieto pakiet


void tablicaKlas (unsigned char* Buffer, int Size){

typedef struct {
		int klasa;
		unsigned char tosbits;
}klasa;

	struct klasa *tablica_klas = malloc(liczbaKlas*sizeof(klasa));

}

void tablicaPakietowOdczytanych () {

unsigned int *liczba_pakietow_odczytanych = malloc(liczbaPortowWyjsciowych*sizeof(liczba_pakietow_odczytanych));

}

void kartaMaPrzerwanie () {

	bool *karta_ma_przerwanie = malloc(liczbaPortowWyjsciowych*sizeof(kartaMaPrzerwanie));
	//Zapis true lub false do tablicy karta_ma_przerwanie

	//Wybrana jest ta karta, z której pobranonajmniej pakietów 
	//i nie była ostatniowybraną kartą, 
	//jeśli więcej niż jedna kartawygenerowała przerwanie
}


void tablicaPolaczen (unsigned char* Buffer, int Size) {

	// getting destination IP address
	long unsigned int dstIpAddress = htonl(dest.sin_addr.s_addr);

	// getting source IP address
	long unsigned int srcIpAddress = htonl(source.sin_addr.s_addr);

	// 3232235719 = 192.168.0.199
	// 3232235691 = 192.168.0.171
	// 3232235718 = 192.168.0.198

	typedef struct polaczenia 
	{
		unsigned int dstIpAddress;
		unsigned int srcIpAddress;
	}polaczenia;

	struct polaczenia *tablica_polaczen = malloc(liczbaPolaczen*sizeof(polaczenia));

	tablica_polaczen[0].dstIpAddress = 3232235719;
	tablica_polaczen[1].dstIpAddress = 3232235691;
	tablica_polaczen[2].dstIpAddress = 3232235718;

	tablica_polaczen[0].srcIpAddress = 3232235691;
	tablica_polaczen[1].srcIpAddress = 3232235719;
	tablica_polaczen[2].srcIpAddress = 3232235718;

	int cnt;
	int failCnt = 1;
	for (cnt =0; cnt< 3; cnt++){

		if ((dstIpAddress == tablica_polaczen[cnt].dstIpAddress) && (srcIpAddress == tablica_polaczen[cnt].srcIpAddress)) {
			fprintf(logfile, "Index that belong to connections table: %d\n", cnt);
		} else {
			fprintf(logfile, "Index that not belong to connections table: %d\n", cnt);
			failCnt++;
		}
	}
	if (failCnt == 3){ // it means that packet with such dst and src address does not exits in connections table
		free(Buffer); // buffer memory is free
	}

	int port_wyjsciowy;
	struct port_wyjsciowy
	{
		int port_wyjsciowy;
		unsigned int dstIpAddress;
	};

	//int cnt;
	for (cnt =0; cnt< 3; cnt++){

		if (tablica_polaczen[0].dstIpAddress = 3232235719) {
			port_wyjsciowy = 1;
			fprintf(logfile, "Output port is %d\n", port_wyjsciowy);
			break;
		} else if (tablica_polaczen[0].dstIpAddress = 3232235718) {
			port_wyjsciowy = 2;
			ffprintf(logfile, "Output port is %d\n", port_wyjsciowy);
			break;
		} else if (tablica_polaczen[0].dstIpAddress = 3232235691) {
			port_wyjsciowy = 3;
			fprintf(logfile, "Output port is %d\n", port_wyjsciowy);
			break;
		} 

	}
}
void odczytajTosBits (unsigned char* Buffer, int Size) {
	
	struct iphdr *iph = (struct iphdr *)Buffer;
	unsigned char tosbits = (unsigned int)iph->tos;

}

