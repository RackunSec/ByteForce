/*
 * ByteForce ver-> yy.mm.dd
 *
 * Douglas Berdeaux
 * WeakNetLabs@gmail.com
 * WeakNet Laboratories
 * WeakNet Academy
 *
 * This application will read binary files
 * and attempt to glean information from
 * weak attempts at obfuscation
 * 
 * This is the quiet verison of this application, can be used for streamlining
 *	data validation processes.
 *
 * GNU (c) 2016 WeakNet Labs
 *
 */
#include<stdio.h>		// for IO
#include<stdlib.h>		// for exit(int)
#include<string.h>		// strcpy();
#include<sys/stat.h>		// file stats
#include<time.h>		// ctime();
#define BFVERSION "1.6.24" 	// update me
unsigned char rot13(unsigned char byte);				// perform a ROT13 on any given byte
void processFile(char * file,int mode); 				// handle the file
void colorText(char * color,char * string);				// print fancy colors
void getHttpString(FILE *fp,unsigned int type,unsigned char xorKey);	// walk through bytes and print them
void byteDecodeSearch(FILE *fp, char * type);				// ROT13, XOR, XOR-ROT13 byte de-obfuscation
int dosPeHeader(FILE *fp);						// DOS PE header check
int pdfHeader(FILE *fp,int fileLength);						// PDF header check

int main(int argc,char ** argv){
	if(argc>2){ // argv[2] could be "--urls"
		if(strcmp(argv[2],"--urls")==0){
			processFile(argv[1],1);
		}
	}else{ // none, just read file:
		processFile(argv[1],0); // this function will process each byte
	}
	return 0;
}

void processFile(char * file,int mode){ /* process each byte in file */
	FILE *fp = fopen(file,"r"); // pointer to opened file
	struct stat fileAttribs; // place our file's attributes here
	unsigned short knownFileType = 0; // Boolean for known file type
	if(fp==NULL){ // what happened?
		fprintf(stderr,"Could not open file %s.\nPlease check the file.\n",file);
	}else{ // file opened OK:
		stat(file,&fileAttribs);
		unsigned int fileLength = fileAttribs.st_size; // get the file length in bytes
		knownFileType = dosPeHeader(fp); // check for DOS/PE headers
		if(!knownFileType) knownFileType = pdfHeader(fp,fileLength); // check for PDF headers
		unsigned int i; // token for looping through each byte
		unsigned char bytes[17];
		long byteCount = 0; // How many bytes read
		// print the header for the data:
		if(mode==0){ // just print the file contents.
			bytes[17] = '\0'; // terminate string
			while(fread(&bytes,1,sizeof(bytes)-1,fp)>0){ // read in chunks of 16 bytes
				unsigned char hex[500];
				sprintf(hex,"| %06x | ",byteCount); // sprintf self-terminates
				for(i=0;i<16;i++){
					sprintf(hex,"%02x ",bytes[i]);
					if(i==7) printf(" "); // formatted output
				}
				for(i=0;i<16;i++){
					if(bytes[i]>=33&&bytes[i]<127){ // printable char:
						sprintf(hex,"%c",bytes[i]);
					}else{ // unprintable char:
						printf(".");
					}
					if(i==7) printf(" "); // formatted output
				}
				strncpy(bytes,"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",16); // blow away value
				byteCount+=16; // update left column
			}
		}else if(mode==1){
			unsigned char byte = '\0';
			unsigned short int httpStringFound = 0; // boolean
			while(fread(&byte,sizeof(byte),1,fp)>0){ // for each byte of the file:
				if(byte==104||byte==72){ // H/h
					fread(&byte,sizeof(byte),1,fp); // grab the next byte
					if(byte==116||byte==84){ // T/t
						fread(&byte,sizeof(byte),1,fp); // grab the next byte
						if(byte==116||byte==84){ // T/t
							fread(&byte,sizeof(byte),1,fp); // grab the next byte
							if(byte==112||byte==80){ // P/p
								// we have an HTTP string!
								httpStringFound=1;
								fseek(fp,-1,SEEK_CUR); // rewind a byte
							}
							fseek(fp,-1,SEEK_CUR); // rewind a byte
						}
						fseek(fp,-1,SEEK_CUR); // rewind a byte
					}
					fseek(fp,-1,SEEK_CUR); // rewind a byte
				}
				if(httpStringFound==1){
					getHttpString(fp,0,'\0'); // 0 == plain text
					httpStringFound=0; // reset me
				}
				byteCount++;
			}
			byteDecodeSearch(fp,"rot13");
			byteDecodeSearch(fp,"xor");
			byteDecodeSearch(fp,"xor-rot13");
		}
	} // finished processing the file, close it up:
	if(fp!=NULL) fclose(fp); // ONLY if it's open, or we segfault
	return;
}

int pdfHeader(FILE *fp,int fileLength){
	unsigned short knownFileType = 0;
	struct pdfHead { // structure for PDF Header bytes
		unsigned char init[5];    // %PDF-
		unsigned char spec[4]; // x.x
	};
	struct pdfHead pdfHeadBytes;
	rewind(fp); // back to the beginning
	fread(&pdfHeadBytes,sizeof(pdfHeadBytes),1,fp);
	if(strncmp("%PDF-",pdfHeadBytes.init,5)==0){
		knownFileType = 1;
		pdfHeadBytes.spec[3] = '\0'; // terminate for printf
	}
	if(knownFileType){ // search byte by byte for executable code:
		unsigned int i;
		unsigned short exeFound = 0;
		unsigned char byte = '\0'; // place the byte temporarily
		rewind(fp);
		// tried using zlib.h deflate/inflate here
		// after looking at code examples, docs, no thanks.
		for(i=0;i<fileLength;i++){
			fread(&byte,sizeof(byte),1,fp);
			if(byte==46){ // .
				fread(&byte,sizeof(byte),1,fp);
				if(byte==101||byte==69){ // E/e - very primitive, I know, but works with some exploits	
					fread(&byte,sizeof(byte),1,fp);
					if(byte==120||byte==88){ // X/x
						fread(&byte,sizeof(byte),1,fp);
						if(byte==101||byte==69){ // E/e
							exeFound=1;
							break; // done. We only need 1 proof.
						}fseek(fp,-1,SEEK_CUR); // and fall-through
					}fseek(fp,-1,SEEK_CUR);
				}fseek(fp,-1,SEEK_CUR);
			}
		}
	}
   	rewind(fp);	
	return knownFileType; // will be true or false
}


int dosPeHeader(FILE *fp){ // check the first few bytes for 4D,59,90 and the 60th byte for the PE
	unsigned char byte = '\0';   // store the byte for fread() temporarily
	unsigned short dosHeader=0;  // is there a DOS header?
	unsigned short peHeaderOk=0; // is this a valid PE file?
	unsigned char peByte = '\0'; // if so, is there a PE pointer?
	rewind(fp); // rewind just in case and we do again before leaving
	fread(&byte,sizeof(byte),1,fp);
	if(byte==77){
		fread(&byte,sizeof(byte),1,fp);
		if(byte==90){
			fread(&byte,sizeof(byte),1,fp);
			if(byte==144){ // NOP
				dosHeader=1;
			}fseek(fp,-1,SEEK_CUR);
		}fseek(fp,-1,SEEK_CUR);
	}fseek(fp,-1,SEEK_CUR);
	if(dosHeader==1){
		fseek(fp,60,SEEK_SET); // 60th byte from beginning is the PE pointer
		fread(&byte,sizeof(byte),1,fp);
		fseek(fp,byte,SEEK_SET); // offset from the beginning of the file
		fread(&byte,sizeof(byte),1,fp); // grab the next byte, is it a "P"?
		if(byte==80){ // P
			fread(&byte,sizeof(byte),1,fp);
			if(byte==69){ // E
				fread(&byte,sizeof(byte),1,fp);
				if(byte==0){ // 0x00
					fread(&byte,sizeof(byte),1,fp);
					if(byte==0){ // 0x00
						peHeaderOk=1;
					}
				}
			}
		}
		if(peHeaderOk==1){
			struct coffHeader{
				unsigned short machine;
				unsigned short numberOfSections;
				long timeDateStamp; // I'm not gonna use most of these
				long pointerToSymbolTable;
				long numberOfSymbols;
				short sizeOfOptionalHeader;
				unsigned short characteristics;
			};
		}
	}
	rewind(fp);
	return dosHeader; // will be true or false
}

void byteDecodeSearch(FILE *fp, char * type){ /* XOR *then* ROT13 bytes in search for case-insensitive http strings */
	rewind(fp);
	unsigned short ti; // integer for easier readability
	if(strcmp("rot13",type)==0){
		ti = 1; // ROT13
	}else if(strcmp("xor",type)==0){
		ti = 2; // XOR
	}else if(strcmp("xor-rot13",type)==0){
		ti = 3; // ROT13->XOR
	}else{

	}
	unsigned char byte = '\0';
	unsigned char byteCount = '\0';
	unsigned short httpStringFound = 0;
	if(ti==1){ // ROT13:
		while(fread(&byte,sizeof(byte),1,fp)>0){ // for each byte of the file:
			byte = rot13(byte);
			if(byte==104||byte==72){ // H/h
				fread(&byte,sizeof(byte),1,fp); // grab the next byte
				byte = rot13(byte);
				if(byte==116||byte==84){ // T/t
					fread(&byte,sizeof(byte),1,fp); // grab the next byte
					byte = rot13(byte);
					if(byte==116||byte==84){ // T/t
						fread(&byte,sizeof(byte),1,fp); // grab the next byte
						byte = rot13(byte);
						if(byte==112||byte==80){ // P/p
							// we have an HTTP string!
							httpStringFound=1;
							fseek(fp,-1,SEEK_CUR); // rewind a byte
						}
						fseek(fp,-1,SEEK_CUR); // rewind a byte
					}
					fseek(fp,-1,SEEK_CUR); // rewind a byte
				}
				fseek(fp,-1,SEEK_CUR); // rewind a byte
			}
			if(httpStringFound==1){
				getHttpString(fp,1,'\0'); // 1 == rot13
				httpStringFound=0; // reset me
			}
			byteCount++;
		}
	}else if(ti==2){ // XOR
		while(fread(&byte,sizeof(byte),1,fp)>0){ // for each byte of the file:
			unsigned char xor = '\x01'; // start at 1 GOTO 1f
			unsigned char xorResult = '\x00'; // to hold the result of XOR
			char xorString[1]; // for each byte we will make a new key
			while(xor<32){ 
				xorResult = xor^byte;
				if(xorResult==104||xorResult==72){ // H/h
					fread(&byte,sizeof(byte),1,fp); // grab the next byte
					xorResult = xor^byte;
					if(xorResult==116||xorResult==84){ // T/t
						fread(&byte,sizeof(byte),1,fp); // grab the next byte
						xorResult = xor^byte;
						if(xorResult==116||xorResult==84){ // T/t
							fread(&byte,sizeof(byte),1,fp); // grab the next byte
							xorResult = xor^byte;
							if(xorResult==112||xorResult==80){ // P/p
								// we have an HTTP string!
								xorString[0] = xor;
								httpStringFound=1;
								fseek(fp,-1,SEEK_CUR); // rewind a byte
							}
							fseek(fp,-1,SEEK_CUR); // rewind a byte
						}
						fseek(fp,-1,SEEK_CUR); // rewind a byte
					}
					fseek(fp,-2,SEEK_CUR); // rewind a byte
					fread(&byte,sizeof(byte),1,fp); // grab the next byte
				}
				if(httpStringFound==1){
					getHttpString(fp,2,xor); // 2 == XOR
					httpStringFound=0; // reset me
				}
				xor++; // try next XOR byte
			}
			xor = '\x01'; // reset it
			byteCount++;  // try the next byte in the file
		}
	}else if(ti==3){ // XOR->ROT13
		// first we unXOR, then we try ROT13
		while(fread(&byte,sizeof(byte),1,fp)>0){ // for each byte of the file:
			unsigned char xor = '\x01'; // start at 1 GOTO 1f
			unsigned char xorResult = '\x00'; // to hold the result of XOR
			char xorString[1]; // for each byte we will make a new key
			while(xor<32){ 
				byte = rot13(byte); // ROT13 it first! Then XOR it
				xorResult = xor^byte;
				if(xorResult==104||xorResult==72){ // H/h
					fread(&byte,sizeof(byte),1,fp); // grab the next byte
					byte = rot13(byte); // we did an fread() so we need to ROT13 again
					xorResult = xor^byte;
					if(xorResult==116||xorResult==84){ // T/t
						fread(&byte,sizeof(byte),1,fp); // grab the next byte
						byte = rot13(byte); // we did an fread() so we need to ROT13 again
						xorResult = xor^byte;
						if(xorResult==116||xorResult==84){ // T/t
							fread(&byte,sizeof(byte),1,fp); // grab the next byte
							byte = rot13(byte); // we did an fread() so we need to ROT13 again
							xorResult = xor^byte;
							if(xorResult==112||xorResult==80){ // P/p
								// we have an HTTP string!
								httpStringFound=1;
								fseek(fp,-1,SEEK_CUR); // rewind a byte
							}
							fseek(fp,-1,SEEK_CUR); // rewind a byte
						}
						fseek(fp,-1,SEEK_CUR); // rewind a byte
					}
					fseek(fp,-2,SEEK_CUR); // rewind a byte
					fread(&byte,sizeof(byte),1,fp); // grab the next byte
					byte = rot13(byte); // we did an fread() so we need to ROT13 again
				}
				if(httpStringFound==1){
					getHttpString(fp,3,xor); // 2 == XOR
					httpStringFound=0; // reset me
				}
				xor++; // try next XOR byte
			}
			xor = '\x01'; // reset it
			byteCount++;  // try the next byte in the file
		}
	}
	return;
}

void getHttpString(FILE *fp,unsigned int type,unsigned char xorKey){
	// type 0 == plain-text, 1 == rot13, 2 == xor, 3 == rot13-xor
	unsigned char byte = '\0';
	unsigned char fmt[500];
	fread(&byte,sizeof(byte),1,fp); // this will be h
	if(type==1){ // ROT 13
		byte = rot13(byte); 
	}else if(type==2) { // XOR
		byte = xorKey^byte;
	}else if(type==3) { // ROT13-XOR
		byte = rot13(byte);
		byte = byte^xorKey;
	}
	while(byte>32&&byte<127){ 
		sprintf(fmt + strlen(fmt),"%c",byte); // breaks
		//colorText("red",fmt);
		fread(&byte,sizeof(byte),1,fp);
		if(type==1){ // ROT 13
			byte = rot13(byte); 
		}else if(type==2) { // XOR
			byte=byte^xorKey;
		}else if(type==3) { // ROT13-XOR
			byte = rot13(byte);
			byte = byte^xorKey;
		}
	}
	sprintf(fmt + strlen(fmt),'\0');// add a null terminater to the fmt string
	printf("%s\n",fmt);
	fmt[0] = '\0'; // terminate string
	return; // file place will be kept since fp is a pointer ;)
}

unsigned char rot13(unsigned char byte){ /* return the rot13() of the byte */
	if((byte > 64 && byte < 78)||(byte > 96 && byte < 110)){
		byte+=13;
	}else if((byte > 77 && byte < 91)||(byte > 109 && byte < 123)){
		byte-=13;
	} // otherwise byte is left alone and returned:
	return byte;
}

void colorText(char * color,char * string){ /* print fancy colors: */
	if(strcmp("yellow",color)==0){ // yellow
		printf("\x1b[33m");
	}else if(strcmp("white",color)==0){ // white
		printf("\e[97m"); 
	}else if(strcmp("grey",color)==0){
		printf("\e[90m");
	}else if(strcmp("orange",color)==0){
		printf("\e[38;5;130m");
	}else if((strcmp("light grey",color)==0)){
		printf("\e[38;5;245m");
	}else if(strcmp("red",color)==0){
		printf("\e[38;5;196m");
	}
	printf("%s",string);
	printf("\x1b[0m"); // reset color
	return; // this function gets rid of a lot of strange strings in the code
}
