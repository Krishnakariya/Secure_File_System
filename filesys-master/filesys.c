#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/sha.h>
#include "filesys.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <errno.h>
#include <error.h>
#include <stdlib.h>

// globals and structs:
struct merkle_node
{
	char node_hash[21];
	int start;
	int end;
	struct merkle_node * left;
	struct merkle_node * right;
	struct merkle_node * parent;
};

struct LinkedListNode
{
	struct merkle_node * m_node;
	struct LinkedListNode * next;
};

struct record{
	int flag;
	char file_name[32];
	char file_hash[21];
	int file_size;
};

struct merkle_node* merkle_roots[1024];
char* filenames[1024];

static int filesys_inited = 0;

//helper functions declarations:

//linked list functions:
struct LinkedListNode * insert_at_end(struct LinkedListNode* head,struct LinkedListNode* elem);
struct LinkedListNode * delete_front(struct LinkedListNode * head);
void print_list(struct LinkedListNode* head);

//merkle tree functions:
struct LinkedListNode * CreateNode(int fd);
struct merkle_node * create_merkle_tree(char* file_name);
char * give_hash_from_merkle_tree(int bno, struct merkle_node * root);
void update_hash_in_merkle_tree(int bno,struct merkle_node * root, char* new_hash);
void print_in_order(struct merkle_node* root);
void free_merkle_tree(struct merkle_node* root);

//secure.txt functions:
int append_to_secure_txt(struct record* record1);
char * get_hash_from_secure_txt(char * file_name);
int update_hash_in_secure_txt(char * file_name, char* hash);
int update_file_size_in_secure_txt(char * file_name, int new_size);
int get_file_size_from_secure_txt(char * file_name);

//filesys init helper function:
int iterate_secure_txt();


/* returns 20 bytes unique hash of the buffer (buf) of length (len)
 * in input array sha1.
 */
void get_sha1_hash (const void *buf, int len, const void *sha1)
{
	SHA1 ((unsigned char*)buf, len, (unsigned char*)sha1);
}

/* Build an in-memory Merkle tree for the file.
 * Compare the integrity of file with respect to
 * root hash stored in secure.txt. If the file
 * doesn't exist, create an entry in secure.txt.
 * If an existing file is going to be truncated
 * update the hash in secure.txt.
 * returns -1 on failing the integrity check.
 */
int s_open (const char *pathname, int flags, mode_t mode)
{
	assert (filesys_inited);
	//1. if file already exists, get hash value from secure.txt, build merkle tree, save it in global array and compare 2 hashes. return -1 if intigrity fails.
	//2. if truck flag was given: update merkle tree as well as hash in secure.txt. (hash=0)
	//3. if file does not exist, check ocreate flag: if yes them create the file, build and save merkle tree and store hash ion secure.txt.
	//4. return 0/1 ? if no intigrity fails.
	char * filename = (char *)malloc(32*sizeof(char));
	strcpy(filename,pathname);
	*(filename+31) = '\0';
	char * hash = get_hash_from_secure_txt(filename);
	int fd;
	if (hash==NULL)
	{
		//file is created firdt time by base.c
		fd = open(pathname,flags,mode);
		if (fd==-1)
		{
			printf("errir in s_open\n");
			free(filename);
			return -1;
		}
		else
		{
			struct record * record1 = (struct record *) malloc(sizeof(struct record));
			strncpy(record1->file_name,filename,32);
			record1->flag = 1;
			record1->file_size =0;
			record1->file_hash[0] ='\0';
			//append_to_secure_txt();

			struct merkle_node * root = (struct merkle_node *)malloc(sizeof(struct record));
			root->left = NULL;
			root->right = NULL;
			root->node_hash[0]= '\0';
			root->parent=NULL;
			root->start=0;
			root->end=0;
			append_to_secure_txt(record1);
			merkle_roots[fd]=root;
			filenames[fd] = filename;
			free(record1); 
			return fd;
		}

	}else
	{

		fd = open(pathname,flags,mode);
		if (fd==-1)
		{
			printf("errir in s_open\n");
			return -1;
		}
		else
		{
			struct merkle_node * root = create_merkle_tree(filename);
			merkle_roots[fd] = root;
			if (strcmp(root->node_hash,hash)!=0)
			{
				free_merkle_tree(merkle_roots[fd]);
				merkle_roots[fd]=NULL;	
				free(filename);
				return -1;
			}
			else
			{
				filenames[fd]=filename;
				return fd;
			}	
			
			
		}

	}
	free(filename);
	return -1;
	//return open (pathname, flags, mode);
}

/* SEEK_END should always return the file size 
 * updated through the secure file system APIs.
 */
int s_lseek (int fd, long offset, int whence)
{
	assert (filesys_inited);
	if((whence & SEEK_END) == SEEK_END)
	{
		int size = get_file_size_from_secure_txt(filenames[fd]);
		return size;
	}
	else
	{
		return lseek (fd, offset, SEEK_SET);
	}
}

/* read the blocks that needs to be updated
 * check the integrity of the blocks
 * modify the blocks
 * update the in-memory Merkle tree and root in secure.txt
 * returns -1 on failing the integrity check.
 */

ssize_t s_write (int fd, const void *buf, size_t count)
{
	assert (filesys_inited);
		
	if (merkle_roots[fd]->node_hash[0]=='\0')
	{
		return write (fd, buf, count);	
	}
	else
	{
		int cur_offset = lseek(fd,0,SEEK_CUR);
		int blockno = cur_offset/64;
		//lseek(fd,blockno*64,SEEK_SET);
		int fd1 = open(filenames[fd] , O_RDONLY, S_IRUSR );
		char* buf1 =(char*)malloc(64*sizeof(char));
		char* hash =(char*)malloc(21*sizeof(char));
		lseek(fd1,blockno*64,SEEK_SET);
		int ret = read(fd1,buf1,64);
		if(ret==-1){
			printf("error in reading in s_write\n");
			return -1;	
		}
		get_sha1_hash(buf1,64,hash);
		*(hash+20)='\0';
		char* original_hash = give_hash_from_merkle_tree(blockno+1,merkle_roots[fd]);
		if(strcmp(original_hash,hash)!=0)
		{	
			free(buf1);
			free(hash);
			return -1;
		}
		else
		{
			int ret1;
			//lseek(fd,cur_offset,SEEK_SET);
			ret1 = write (fd, buf, count);
			//int final_offset = lseek(fd,0,SEEK_CUR);
			if(ret1 == -1)
			{	
				printf("error in s_write\n");
				free(buf1);
				free(hash);
				return -1;
			}
			lseek(fd1,blockno*64,SEEK_SET);
			ret = read(fd1,buf1,64);
			if(ret==-1){
				printf("error in reading in s_write\n");
				return -1;	
			}
			get_sha1_hash(buf1,64,hash);
			*(hash+20)='\0';
			update_hash_in_merkle_tree(blockno+1,merkle_roots[fd],hash);
			update_hash_in_secure_txt(filenames[fd],merkle_roots[fd]->node_hash);
			free(buf1);
			free(hash);
			//lseek(fd,final_offset,SEEK_SET);
			close(fd1);
			return ret1;	
		}
		return -1;
	}	
	//return write (fd, buf, count);
}

/* check the integrity of blocks containing the 
 * requested data.
 * returns -1 on failing the integrity check.
 */
ssize_t s_read (int fd, void *buf, size_t count)
{
	assert (filesys_inited);
	int cur_offset = lseek(fd,0,SEEK_CUR);
	int blockno = cur_offset/64;
	lseek(fd,blockno*64,SEEK_SET);
	char* buf1 =(char*)malloc(64*sizeof(char));
	char* hash =(char*)malloc(21*sizeof(char));
	
	int ret = read(fd,buf1,64);
	if(ret==-1){
		printf("error in reading in s_read\n");
		return -1;	
	}
	get_sha1_hash(buf1,64,hash);
	*(hash+20)='\0';
	char* original_hash = give_hash_from_merkle_tree(blockno+1,merkle_roots[fd]);
	if(strcmp(original_hash,hash)!=0)
	{	
		free(buf1);
		free(hash);
		return -1;
	}
	ret = read(fd,buf1,64);
	if(ret==-1){
		printf("error in reading in s_read\n");
		return -1;	
	}
	get_sha1_hash(buf1,64,hash);
	*(hash+20)='\0';
	original_hash = give_hash_from_merkle_tree(blockno+1,merkle_roots[fd]);
	if(strcmp(original_hash,hash)!=0)
	{	
		free(buf1);
		free(hash);
		return -1;
	}

	lseek(fd,cur_offset,SEEK_SET);
	return read(fd,buf,count);
	// for (int i = 0; i < 3; ++i)
	// {
		// int ret = read(fd,buf1,64);
		// if(ret==-1){
		// 	printf("error in reading in s_read\n");
		// 	return -1;	
		// }
		// get_sha1_hash(buf1,64,hash);
		// *(hash+20)='\0';
		// char* original_hash = give_hash_from_merkle_tree(blockno+1,merkle_roots[fd]);
	// 	//if(cur_offset == 128*999){
	// 		printf("%d\n",i);
	// 		printf("\n");
	// 		printf("%s\n",original_hash);
	// 	//}
	// 	// printf("hello\n");
		// if(strcmp(original_hash,hash)!=0)
		// {	
		// 	free(buf1);
		// 	free(hash);
		// 	return -1;
		// }
	// 	else
	// 	{
	// 		// printf("%d\n",i);
	// 		if(cur_offset + count < (blockno+1)*64 )
	// 		{
	// 			lseek(fd,cur_offset,SEEK_SET);
	// 			return read (fd, buf, count);			
	// 		}
	// 		else
	// 		{
	// 			blockno+=1;
	// 		}
	// 	}
	// }
	printf("error in s_read\n");
	return -1;
}

/* destroy the in-memory Merkle tree */
int s_close (int fd)
{
	assert (filesys_inited);
	if (merkle_roots[fd]->node_hash[0]=='\0')
	{
		int file_size = lseek(fd,0,SEEK_END);
		update_file_size_in_secure_txt(filenames[fd],file_size);
		struct merkle_node * root = create_merkle_tree(filenames[fd]);
		update_hash_in_secure_txt(filenames[fd],root->node_hash);
		free_merkle_tree(root);	
		free_merkle_tree(merkle_roots[fd]);
		merkle_roots[fd] = NULL;
		filenames[fd] = NULL;
		return close(fd);
	}
	else
	{
		free_merkle_tree(merkle_roots[fd]);
		free(filenames[fd]);

		return close(fd);
	}		

	return -1;
}

/* Check the integrity of all files in secure.txt
 * remove the non-existent files from secure.txt
 * returns 1, if an existing file is tampered
 * return 0 on successful initialization
 */
int filesys_init (void)
{
	//0. create secure.txt if it doesn't exist. clear all the in memory merkle trees.
	//iterate through all records in secure.txt and 
	//1. remove non existant files.
	//2. if amy file is tampered then return 1.
	//3. if no file is tampered return 0.
	int ret;
	ret = iterate_secure_txt();
	if (ret==1)
	{
		return 1;
	}
	else if (ret ==0)
	{
		filesys_inited = 1;
		return 0;
	}
	else
	{
		printf("error in filesys_init\n");
		return -1;
	}
}



// helper function definition:

// linked list functions:
struct LinkedListNode * insert_at_end(struct LinkedListNode* head,struct LinkedListNode* elem){
	if(head==NULL)
	{
		head=elem;
		return head;
	}
	struct LinkedListNode* head1 = head;
	struct LinkedListNode* prev = NULL;
	while(head1!=NULL)
	{
		prev = head1;
		head1=head1->next;
	}
	prev->next = elem;
	return head;
}

struct LinkedListNode * delete_front(struct LinkedListNode * head){
	if(head==NULL)
	{
		return NULL;
	}
	struct LinkedListNode* temp = head;
	head = head->next;
	free(temp);
	return head;
}

void print_list(struct LinkedListNode* head){
	struct LinkedListNode* head1 = head;
	while(head1!=NULL){
		if(head1->m_node != NULL)
		{
			printf("%d %d \n",head1->m_node->start,head1->m_node->end);			
		}
		else
		{
			printf("marker\n");
		}
		head1=head1->next;
	}
	printf("\n");
}


// merkle tree functions:

struct LinkedListNode * CreateNode(int fd){
	char * buf = (char *)malloc(64*(sizeof(char)));
	char * hash = (char *)malloc(21*(sizeof(char)));
	int ret;
	
	struct LinkedListNode * queue = NULL; 
	int count = 0;
	lseek(fd,0,SEEK_SET);
	while((ret = read(fd,buf,64))>0)
	{
		count+=1;
		get_sha1_hash(buf,64,hash);
		*(hash+20)='\0';
		struct LinkedListNode* elem = (struct LinkedListNode*)malloc(sizeof(struct LinkedListNode));
		
		elem->m_node = (struct merkle_node*)malloc(sizeof(struct merkle_node));
		strcpy(elem->m_node->node_hash,hash);
		elem->m_node->start = count;
		elem->m_node->end = count;
		elem->m_node->left = NULL;
		elem->m_node->right = NULL;
		elem->next = NULL;
		queue = insert_at_end(queue,elem);
	}

	struct LinkedListNode* elem = (struct LinkedListNode*)malloc(sizeof(struct LinkedListNode));
	elem->next = NULL;
	elem->m_node = NULL;
	queue = insert_at_end(queue,elem);
	
	free(hash);
	free(buf);
	return queue;
}

struct merkle_node * create_merkle_tree(char* file_name)
{
	int fd = open(file_name,O_RDONLY,S_IRUSR);
	if(fd == -1)
	{
		printf("error in create_merkle_tree\n");
	}
	struct LinkedListNode * queue = CreateNode(fd);
	//printf("hi\n");
	char* hash_of_node = (char*)malloc(41*sizeof(char));
	char* val = (char*)malloc(21*sizeof(char));
	struct merkle_node* left;
	struct merkle_node* right;
	while(queue!=NULL){
		if(queue->m_node == NULL)	
		{
			queue = delete_front(queue);
			struct LinkedListNode* elem = (struct LinkedListNode*)malloc(sizeof(struct LinkedListNode));
			elem->m_node = NULL;
			elem->next = NULL;
			queue = insert_at_end(queue,elem);
			continue;
		}
		strncpy(hash_of_node,queue->m_node->node_hash,20);
		left = queue->m_node; // may create prob.
		queue = delete_front(queue);
		if(queue->m_node!=NULL)
		{
			strncpy(hash_of_node+20,queue->m_node->node_hash,21);
			
			right = queue->m_node;
			queue = delete_front(queue);

			struct LinkedListNode* elem = (struct LinkedListNode*)malloc(sizeof(struct LinkedListNode));
			
			elem->m_node = (struct merkle_node*)malloc(sizeof(struct merkle_node));
			elem->m_node->left = left;
			elem->m_node->right = right; 
			left->parent = elem->m_node;
			right->parent = elem->m_node;
			elem->next =  NULL;
			get_sha1_hash(hash_of_node,40,val);
			strcpy(elem->m_node->node_hash,val);
			*(elem->m_node->node_hash+20)='\0';
			elem->m_node->start = left->start;
			elem->m_node->end = right->end;
			queue = insert_at_end(queue,elem);
		}
		else
		{
			if(queue->next==NULL){
				return left;
			}
			struct LinkedListNode* elem = (struct LinkedListNode*)malloc(sizeof(struct LinkedListNode));
			elem->m_node=left;
			elem->next = NULL;
			queue = insert_at_end(queue,elem);
			queue = delete_front(queue);
			struct LinkedListNode* elem1 = (struct LinkedListNode*)malloc(sizeof(struct LinkedListNode));
			elem1->next = NULL;
			elem1->m_node = NULL;
			queue = insert_at_end(queue,elem1);
			continue;	
		}
	}
	return NULL;
}

char * give_hash_from_merkle_tree(int bno, struct merkle_node * root)
{
	if(root==NULL){
		return NULL;
	}
	if(root->start == bno && root->end == bno)
	{
		return root->node_hash;
	}
	else if(root->start <= bno && bno <= root->end)
	{
		char * left = give_hash_from_merkle_tree(bno,root->left);
		char* right = give_hash_from_merkle_tree(bno,root->right);
		if(left==NULL){
			return right;
		}
		else{
			return left;
		}
	}
	else
	{
		return NULL;
	}
} 

void update_hash_in_merkle_tree(int bno,struct merkle_node * root, char* new_hash)
{
	if(root==NULL)
	{
		return ;
	}
	if(root->start == bno && root->end == bno)
	{
		strcpy(root->node_hash,new_hash);
		return;
	}
	else if(root->start <= bno && bno <= root->end)
	{
		char* get_hash = (char *)malloc(41*sizeof(char));
		update_hash_in_merkle_tree(bno,root->left,new_hash);
		update_hash_in_merkle_tree(bno,root->right,new_hash);
		strncpy(get_hash,root->left->node_hash,20);
		strncpy(get_hash + 20,root->left->node_hash,20);
		*(get_hash + 40) = '\0';
 		get_sha1_hash(get_hash,40,root->node_hash);
 		free(get_hash);
 		return;
	}
	else{
		return ;
	}
}

void print_in_order(struct merkle_node* root)
{
	if(root!=NULL)
	{
		print_in_order(root->left);
		printf("%d %d\n",root->start,root->end);
		print_in_order(root->right);
	}
}

void free_merkle_tree(struct merkle_node* root)
{
	if(root==NULL){
		return;
	}
	if(root->left==NULL && root->right ==NULL)
	{
		free(root);
		return ;
	}
	free_merkle_tree(root->left);
	free_merkle_tree(root->right);
	free(root);
}


// secure.txt functions:

int append_to_secure_txt(struct record* record1)// make sure to free record1 after calling this function.
{
	//secure.txt opening logic in append mode:
	
	FILE * secure ;
	secure = fopen("secure.txt","a+");
	if(secure == NULL){
		printf("error in opening2 in insert_record_to_secure_txt \n");
		return -1;	
	}

	// appendind logic:
	int ret = fwrite(record1,sizeof(struct record),1,secure);
	if (ret != 1)
	{
		printf("error in writing to secure.txt in append_to_secure_txt\n");
		return -1;
	}
	fclose(secure);
	return 1;
}

char * get_hash_from_secure_txt(char * file_name)
{
	// secure.txt opening logic in r/w mode.
	FILE * secure ;
	secure = fopen("secure.txt","a+");
	if(secure == NULL){
		printf("error in opening1 in insert_record_to_secure_txt \n");
		return NULL;
	}
	fclose(secure);
	secure = fopen("secure.txt","r");
	if(secure == NULL){
		printf("error in opening2 in insert_record_to_secure_txt \n");
		return NULL;
	}

	// reading hash value logic:
	struct record * record1 =(struct record * )malloc(sizeof(struct record));
	int ret;
	while(1)
	{
		ret = fread(record1,sizeof(struct record),1,secure);
		if(ret!=1)
		{
			//printf("secure.txt ended, connot find filename in get_hash_from_secure_txt\n");
			fclose(secure);
			free(record1);
			return NULL;
		}
		if (record1->flag==1 && strcmp(record1->file_name,file_name)==0){
			char * temp = (char *)malloc(21*sizeof(char));
			strcpy(temp,record1->file_hash);
			fclose(secure);
			free(record1);
			return temp;
		}
	}	
	fclose(secure);
	free(record1);
	return NULL;
}
int get_file_size_from_secure_txt(char * file_name)
{
	// secure.txt opening logic in r/w mode.
	FILE * secure ;
	secure = fopen("secure.txt","a+");
	if(secure == NULL){
		printf("error in opening1 in insert_record_to_secure_txt \n");
		return -1;
	}
	fclose(secure);
	secure = fopen("secure.txt","r");
	if(secure == NULL){
		printf("error in opening2 in insert_record_to_secure_txt \n");
		return -1;
	}

	// reading hash value logic:
	struct record * record1 =(struct record * )malloc(sizeof(struct record));
	int ret;
	while(1)
	{
		ret = fread(record1,sizeof(struct record),1,secure);
		if(ret!=1)
		{
			printf("secure.txt ended, connot find filename in get_hash_from_secure_txt\n");
			fclose(secure);
			free(record1);
			return -1;
		}
		if (record1->flag==1 && strcmp(record1->file_name,file_name)==0){
			//char * temp = (char *)malloc(21*sizeof(char));
			//strcpy(temp,record1->file_hash);
			int temp = record1->file_size;
			fclose(secure);
			free(record1);
			return temp;
		}
	}	
	fclose(secure);
	free(record1);
	return -1;
}

int update_hash_in_secure_txt(char * file_name, char* hash)
{
	FILE * secure ;
	secure = fopen("secure.txt","a+");
	if(secure == NULL){
		printf("error in opening1 in update_hash_in_secure_txt \n");
		return -1;
	}
	fclose(secure);
	secure = fopen("secure.txt","r+");
	if(secure == NULL){
		printf("error in opening2 in update_hash_in_secure_txt \n");
		return -1;
	}
	// updating hash value logic:
	struct record * record1 =(struct record * )malloc(sizeof(struct record));
	int ret,count=0;
	while(1)
	{
		ret = fread(record1,sizeof(struct record),1,secure);
		if(ret!=1)
		{
			printf("secure.txt ended, connot find filename in update_hash_in_secure_txt\n");
			fclose(secure);
			free(record1);
			return -1;
		}
		if (record1->flag==1 && strcmp(record1->file_name,file_name)==0){
			ret = fseek(secure,count,SEEK_SET);
			if(ret==-1){
				printf("error in fseek in update_hash_in_secure_txt %d\n",ret);
			}
			strcpy(record1->file_hash,hash);
			
			ret = fwrite(record1,sizeof(struct record),1,secure);
			if (ret != 1)
			{
				printf("error in writing to secure.txt in update_hash_in_secure_txt\n");
				return -1;
			}
			fclose(secure);
			free(record1);
			return 1;
		}
		count+=sizeof(struct record);
	}	
	fclose(secure);
	free(record1);
	return -1;	
}
	
int update_file_size_in_secure_txt(char * file_name, int new_size)
{
	FILE * secure ;
	secure = fopen("secure.txt","a+");
	if(secure == NULL){
		printf("error in opening1 in update_file_size_in_secure_txt \n");
		return -1;
	}
	fclose(secure);
	secure = fopen("secure.txt","r+");
	if(secure == NULL){
		printf("error in opening2 in update_file_size_in_secure_txt \n");
		return -1;
	}
	// updating hash value logic:
	struct record * record1 =(struct record * )malloc(sizeof(struct record));
	int ret,count=0;
	while(1)
	{
		ret = fread(record1,sizeof(struct record),1,secure);
		if(ret!=1)
		{
			printf("secure.txt ended, connot find filename in update_file_size_in_secure_txt\n");
			fclose(secure);
			free(record1);
			return -1;
		}
		if (record1->flag==1 && strcmp(record1->file_name,file_name)==0){
			ret = fseek(secure,count,SEEK_SET);
			if(ret==-1){
				printf("error in fseek in update_file_size_in_secure_txt %d\n",ret);
			}
			//strcpy(record1->file_hash,hash);
			record1->file_size = new_size;
			ret = fwrite(record1,sizeof(struct record),1,secure);
			if (ret != 1)
			{
				printf("error in writing to secure.txt in update_file_size_in_secure_txt\n");
				return -1;
			}
			fclose(secure);
			free(record1);
			return 1;
		}
		count+=sizeof(struct record);
	}	
	fclose(secure);
	free(record1);
	return -1;	
}


// filesys init helper func:

int iterate_secure_txt() // return value is ret value of final fread(). Return 1 if integrity if any file is compramized. Ret value is -1 if some error. ret is 0 is filesys_init is successful
{
	for (int i = 0; i < 1024; ++i)
	{
		if(merkle_roots[i]!=NULL)
		{
			free_merkle_tree(merkle_roots[i]);
			merkle_roots[i] = NULL;
		} 
	}	
	// secure.txt opening logic in r/w mode.
	FILE * secure ;
	secure = fopen("secure.txt","a+");
	if(secure == NULL){
		printf("error in opening1 in iterate_secure_txt \n");
		return -1;
	}
	fclose(secure);
	secure = fopen("secure.txt","r+");
	if(secure == NULL){
		printf("error in opening2 in iterate_secure_txt \n");
		return -1;
	}

	// filesysinit logic:
	struct record * record1 =(struct record * )malloc(sizeof(struct record));
	int ret;
	int count=0;
	while(1)
	{
		
		ret = fread(record1,sizeof(struct record),1,secure);
		if(ret!=1)
		{
			//at here we return since whole file is iterated.
			//printf("secure.txt ended, connot find filename in get_hash_from_secure_txt\n");
			fclose(secure);
			free(record1);
			return ret;
		}
		if (record1->flag==1){
			char * filename = record1->file_name;
			ret = open(filename,O_RDWR, 0);
			if (ret ==-1)
			{
				record1->flag =0;
				ret = fseek(secure,count,SEEK_SET);
				if(ret != 0)
				{
					printf("error in fseek in iterate_secure_txt\n");
				}
				ret = fwrite(record1,sizeof(struct record),1,secure);
				if(ret != 1)
				{
					printf("error in write in iterate_secure_txt\n");
				}
			//	printf("hhhhhhhh\n");
			}
			else
			{
				struct merkle_node * merkle_root = create_merkle_tree(filename);
				if (strcmp(merkle_root->node_hash,record1->file_hash)!=0)
				{
					free_merkle_tree(merkle_root);
					fclose(secure);
					free (record1);
					return 1; // existing file is tampered.
				}
				else{
					//printf("successful\n");
				}
				free_merkle_tree(merkle_root);
				close(ret);
			}
		}
		count+=sizeof(struct record);
	}	
	fclose(secure);
	free(record1);
	printf("done\n");
	return 0;
}