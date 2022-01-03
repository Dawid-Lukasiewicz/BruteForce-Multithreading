/****************************************************************
* AUTHOR:   Dawid Łukasiewicz
* COMPILE:  gcc zad1.c -lssl -lcrypto
****************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <pthread.h>
#include <openssl/md5.h>

#define STRING_SIZE 50
#define NUMTHRDS 4
// Global variables for threads
pthread_mutex_t mut;
pthread_mutex_t mutex_thread_done;
pthread_cond_t cond_mutex;

int SizePassToCrack, SizePassDictionary;
int ThreadsFinished = 0;
int SolvedCount = 0;
FILE *PasswFile1M, *PasswFileDict;
char **PassToCrack, **PassDictionary;
char **Solved;

char* md5(const char *str, int length) {
    int n;
    MD5_CTX c;
    unsigned char digest[MD5_DIGEST_LENGTH];
    char *out = (char*)malloc(MD5_DIGEST_LENGTH * 2 + 1);

    MD5_Init(&c);

    while (length > 0) {
        if (length > 512) {
            MD5_Update(&c, str, 512);
        } else {
            MD5_Update(&c, str, length);
        }
        length -= 512;
        str += 512;
    }

    MD5_Final(digest, &c);

    for (n = 0; n < MD5_DIGEST_LENGTH; ++n) {
        snprintf(&(out[n*2]), MD5_DIGEST_LENGTH*2, "%02x", (unsigned int)digest[n]);
    }

    out[MD5_DIGEST_LENGTH * 2] = '\0';

    return out;
}

int MakeTablePass(char ***OriginalTablePass, FILE *file)
{
    int CountRows = 0;
    char TmpChar[STRING_SIZE];
    char **TablePass;
    while (!feof(file))
    {
        if(fgets(TmpChar, STRING_SIZE, file) != NULL)
        {
            CountRows++;        
        }
    }

    rewind(file);

    TablePass = (char**)malloc(CountRows*sizeof(char*));
    for (int i = 0; i < CountRows; i++)
    {
        TablePass[i] = (char*)malloc(STRING_SIZE*sizeof(char));
        if(fgets(TablePass[i], STRING_SIZE, file) == NULL)
        {
            exit(1);
        }
    }
    *OriginalTablePass = TablePass;
    return CountRows;
}

void FindPassword(int i)
{
    char *DictionaryHashedWord = md5(PassDictionary[i], strlen(PassDictionary[i]));

    for (int k = 0; k < SizePassToCrack; k++)
    {
        // Skip if password found earlier
        if(PassToCrack[k] == "\0")
        {
            continue;
        }
        else if(strcmp(DictionaryHashedWord, PassToCrack[k]) == 0)
        {
            // Erasing password here if found
            pthread_mutex_lock(&mut);
            PassToCrack[k] = "\0";  // Now you can't free this dynamically allocated table. Is it caused by assigning a const char*? 
            Solved[SolvedCount] = PassDictionary[i];
            SolvedCount++;

            // Telling watcher to wake up
            pthread_cond_signal(&cond_mutex);

            pthread_mutex_unlock(&mut);
            break;
        }
        else
        {
            /** I probably need addittional loop to add more chars **/
            // Do ModPass1 dopisywane są znaki na końcu
            // Do ModPass2 na początku
            char ModPass1[STRING_SIZE], ModPass2[STRING_SIZE], Helper1[STRING_SIZE], Helper2[STRING_SIZE];
            char AsciToChar[4];
            bool Find = false;
            for (int d = 33; d < 127; d++)
            {
                // Copying dictionary password
                strncpy(ModPass1, PassDictionary[i], strlen(PassDictionary[i]) - 1);
                strncpy(Helper2, PassDictionary[i], strlen(PassDictionary[i]));
                // Getting char from ascii
                sprintf(AsciToChar, "%c\n", d);
                strcpy(Helper1, AsciToChar);
                strncpy(ModPass2, AsciToChar, strlen(AsciToChar) - 1);
                // Merging dictionary password with new letter
                strcat(ModPass1, Helper1);
                strcat(ModPass2, Helper2);
                
                printf("%s %s", ModPass1, ModPass2);

                if(strcmp(md5(ModPass1, strlen(ModPass1)), PassToCrack[k]) == 0)
                {
                    // Erasing password here if found
                    pthread_mutex_lock(&mut);
                    PassToCrack[k] = "\0";
                    Solved[SolvedCount] = ModPass1;
                    SolvedCount++;

                    // Telling watcher to wake up
                    pthread_cond_signal(&cond_mutex);

                    pthread_mutex_unlock(&mut);
                    Find = true;
                    break;
                }
                else if(strcmp(md5(ModPass2, strlen(ModPass2)), PassToCrack[k]) == 0)
                {
                    // Erasing password here if found
                    pthread_mutex_lock(&mut);
                    PassToCrack[k] = "\0";
                    Solved[SolvedCount] = ModPass2;
                    SolvedCount++;

                    // Telling watcher to wake up
                    pthread_cond_signal(&cond_mutex);

                    pthread_mutex_unlock(&mut);
                    Find = true;
                    break;
                }
                // Clearing strings variables
                memset(ModPass1, 0, strlen(ModPass1));
                memset(ModPass2, 0, strlen(ModPass2));
                memset(Helper1, 0, strlen(Helper1));
                memset(Helper2, 0, strlen(Helper2));
                
                sleep(1);
            }
            if (Find == true)
                break;
            
        }
    }
}

void *OnlyCharacter(void *arg)
{
    long id = (long)arg;
    bool character, integer;
    for (int i = 0; i < SizePassDictionary; i++)
    {
        character = false;
        integer = false;
        for (int k = 0; k < strlen(PassDictionary[i])-1; k++)
        {
            if(isalpha(PassDictionary[i][k]))
                character = true;
            else
                integer = true;
            if(integer && character)
                break;
        }

        if(integer) //If containing digit skip loop
            continue;
    
        FindPassword(i);
    }
    pthread_mutex_lock(&mutex_thread_done);
    ThreadsFinished++;
    pthread_mutex_unlock(&mutex_thread_done);
    pthread_exit((void*) 0);
}

void *MixedComparison(void *arg)
{
    long id = (long)arg;
    bool character, integer;
    for (int i = 0; i < SizePassDictionary; i++)
    {
        character = false;
        integer = false;
        for (int k = 0; k < strlen(PassDictionary[i])-1; k++)
        {
            if(isalpha(PassDictionary[i][k]))
                character = true;
            else
                integer = true;
            if(integer && character)
                break;
        }

        if((integer == true && character == false) 
            || (integer == false && character == true) ) //Skip if string not numbers nor letters
        {
            continue;
        }
        FindPassword(i);
    }
    pthread_mutex_lock(&mutex_thread_done);
    ThreadsFinished++;
    pthread_mutex_unlock(&mutex_thread_done);
    pthread_exit((void*) 0);
}

void *OnlyNumber(void *arg)
{
    long id = (long)arg;
    bool character, integer;
    for (int i = 0; i < SizePassDictionary; i++)
    {
        character = false;
        integer = false;
        for (int k = 0; k < strlen(PassDictionary[i])-1; k++)
        {
            if(isalpha(PassDictionary[i][k]))
                character = true;
            else
                integer = true;
            if(integer && character)
                break;
        }

        if(character)  //If first character not a digit skip loop
            continue;

        FindPassword(i);
    }
    pthread_mutex_lock(&mutex_thread_done);
    ThreadsFinished++;
    pthread_mutex_unlock(&mutex_thread_done);
    pthread_exit((void*) 0);
}

void *Watcher(void *arg)
{
    int PrintedSolved = 0;

    pthread_mutex_lock(&mut);
    while (ThreadsFinished < NUMTHRDS - 1)
    {
        printf("Waiting\n");
        pthread_cond_wait(&cond_mutex, &mut);

        // When woken up print out new passwords found
        for (PrintedSolved; PrintedSolved < SolvedCount; PrintedSolved++)
        {
            printf("PrintedSolved %d\t %d\n", PrintedSolved, SolvedCount);
            printf("Solved %d: %s\n",PrintedSolved, Solved[PrintedSolved]);    
        }
    }
    pthread_mutex_unlock(&mut);

    printf("Found %d password\n", SolvedCount);
    pthread_exit((void*) 0);
}

int main(int argc, char *argv[])
{   
    pthread_t threads[NUMTHRDS];
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    pthread_mutex_init(&mut, NULL);
    pthread_mutex_init(&mutex_thread_done, NULL);
    pthread_cond_init(&cond_mutex, NULL);

    PasswFileDict = fopen("passwords-million.txt", "r");
    PasswFile1M = fopen("passwords1.txt", "r");
    if(PasswFile1M == NULL || PasswFileDict == NULL)
    {
        printf("One of files not opened correctly\n");
        exit(-1);
    }

    SizePassToCrack = MakeTablePass(&PassToCrack, PasswFile1M);
    SizePassDictionary = MakeTablePass(&PassDictionary, PasswFileDict);

    // Closing files
    fclose(PasswFile1M);
    fclose(PasswFileDict);

    // Hashing passwords and allocating memory for table of solved passwords
    Solved = (char**)malloc(SizePassToCrack*sizeof(char*));
    for (int i = 0; i < SizePassToCrack; i++)
    {
        Solved[i] = (char*)malloc(STRING_SIZE*sizeof(char));
        Solved[i] = NULL;   //Solved is NULL at start, neccessary for condition
        PassToCrack[i] = md5(PassToCrack[i], strlen(PassToCrack[i]));
    }

    // pthread_create(&threads[3], &attr, Watcher, (void*)3);
    // sleep(3);
    pthread_create(&threads[0], &attr, OnlyCharacter, (void*)0);
    // pthread_create(&threads[1], &attr, MixedComparison, (void*)1);
    // pthread_create(&threads[2], &attr, OnlyNumber, (void*)2);
    
    
    pthread_attr_destroy(&attr);
    pthread_join(threads[0], NULL);
    // pthread_join(threads[1], NULL);
    // pthread_join(threads[2], NULL);
    // pthread_join(threads[3], NULL);

    pthread_cond_destroy(&cond_mutex);
    // Freeing allocated memory
    
    for (int i = 0; i < SizePassDictionary; i++)
    {
        free(PassDictionary[i]);
    }
    free(PassDictionary);
	
	return 0;
}