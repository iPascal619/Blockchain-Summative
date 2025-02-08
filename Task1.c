#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>

// Constants and configuration
#define DIFFICULTY 4
#define MAX_TRANSACTIONS 100
#define MAX_ITEM_ID_LENGTH 64
#define MAX_DESCRIPTION_LENGTH 256
#define MAX_SIGNATURE_LENGTH 256
#define SHA256_LENGTH 32 
#define HASH_STRING_LENGTH (SHA256_LENGTH * 2 + 1) 
#define MAX_BUFFER_SIZE 4096


// Error codes
typedef enum {
    SUCCESS = 0,
    ERROR_INVALID_PARAM = -1,
    ERROR_MEMORY_ALLOCATION = -2,
    ERROR_BLOCKCHAIN_FULL = -3,
    ERROR_INVALID_TRANSACTION = -4
} ErrorCode;

// Transaction structure 
typedef struct {
    char item_id[MAX_ITEM_ID_LENGTH];
    char description[MAX_DESCRIPTION_LENGTH];
    char signature[MAX_SIGNATURE_LENGTH];
    time_t timestamp;  
} Transaction;

// Block structure
typedef struct Block {
    int index;
    time_t timestamp;
    struct Block *previous_block;
    Transaction transactions[MAX_TRANSACTIONS];  
    int num_transactions;
    char hash[HASH_STRING_LENGTH];
    char previous_hash[HASH_STRING_LENGTH];
    int nonce;
    struct Block *next_block;
} Block;

// Blockchain structure
typedef struct {
    Block *genesis_block;
    Block *latest_block;
    int total_blocks;
    int difficulty;  
} Blockchain;

// Function prototypes
Blockchain* create_blockchain(int difficulty);
ErrorCode compute_sha256_hash(const char *str, char *hash_out, size_t hash_size);
ErrorCode compute_block_hash(const Block *block, char *hash_out, size_t hash_size);
ErrorCode mine_block(Block *block, int difficulty);
ErrorCode validate_transaction(const Transaction *tx);
ErrorCode add_transaction_to_block(Block *block, const Transaction *tx);
void cleanup_blockchain(Blockchain *blockchain);
Block* create_block(Blockchain *blockchain);
void print_blockchain(const Blockchain *blockchain);
void run_cli(Blockchain *blockchain);

ErrorCode compute_sha256_hash(const char *str, char *hash_out, size_t hash_size) {
    if (!str || !hash_out || hash_size < HASH_STRING_LENGTH) {
        return ERROR_INVALID_PARAM;
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        return ERROR_MEMORY_ALLOCATION;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        return ERROR_INVALID_PARAM;
    }

    if (EVP_DigestUpdate(mdctx, str, strlen(str)) != 1) {
        EVP_MD_CTX_free(mdctx);
        return ERROR_INVALID_PARAM;
    }

    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        return ERROR_INVALID_PARAM;
    }

    EVP_MD_CTX_free(mdctx);

    // Convert to hex string
    for (unsigned int i = 0; i < hash_len; i++) {
        snprintf(hash_out + (i * 2), 3, "%02x", hash[i]);
    }
    
    return SUCCESS;
}

// Block hash computation function
ErrorCode compute_block_hash(const Block *block, char *hash_out, size_t hash_size) {
    if (!block || !hash_out || hash_size < HASH_STRING_LENGTH) {
        return ERROR_INVALID_PARAM;
    }

    char *block_data = (char *)malloc(MAX_BUFFER_SIZE);
    if (!block_data) {
        return ERROR_MEMORY_ALLOCATION;
    }

    int offset = snprintf(block_data, MAX_BUFFER_SIZE, "%d%ld%s%d", 
        block->index, block->timestamp, block->previous_hash, block->nonce);
    
    for (int i = 0; i < block->num_transactions; i++) {
        offset += snprintf(block_data + offset, MAX_BUFFER_SIZE - offset, "%s%s%s%ld",
            block->transactions[i].item_id,
            block->transactions[i].description,
            block->transactions[i].signature,
            block->transactions[i].timestamp);
    }

    ErrorCode result = compute_sha256_hash(block_data, hash_out, hash_size);
    free(block_data);
    return result;
}

// Create new block function
Block* create_block(Blockchain *blockchain) {
    if (!blockchain) {
        return NULL;
    }

    Block *block = (Block *)malloc(sizeof(Block));
    if (!block) {
        return NULL;
    }

    block->index = blockchain->total_blocks;
    block->timestamp = time(NULL);
    block->previous_block = blockchain->latest_block;
    block->next_block = NULL;
    block->num_transactions = 0;
    block->nonce = 0;

    if (blockchain->latest_block) {
        strncpy(block->previous_hash, blockchain->latest_block->hash, HASH_STRING_LENGTH - 1);
        block->previous_hash[HASH_STRING_LENGTH - 1] = '\0';
    } else {
        strncpy(block->previous_hash, "0", HASH_STRING_LENGTH - 1);
        block->previous_hash[HASH_STRING_LENGTH - 1] = '\0';
    }

    if (!blockchain->genesis_block) {
        blockchain->genesis_block = block;
    } else if (blockchain->latest_block) {
        blockchain->latest_block->next_block = block;
    }
    blockchain->latest_block = block;
    blockchain->total_blocks++;

    return block;
}

// Mining function
ErrorCode mine_block(Block *block, int difficulty) {
    if (!block || difficulty < 1) {
        return ERROR_INVALID_PARAM;
    }

    char hash[HASH_STRING_LENGTH];
    char target[HASH_STRING_LENGTH];
    
    memset(target, '0', difficulty);
    target[difficulty] = '\0';

    do {
        block->nonce++;
        if (compute_block_hash(block, hash, sizeof(hash)) != SUCCESS) {
            return ERROR_INVALID_PARAM;
        }
    } while (strncmp(hash, target, difficulty) != 0);

    strncpy(block->hash, hash, HASH_STRING_LENGTH - 1);
    block->hash[HASH_STRING_LENGTH - 1] = '\0';
    
    printf("Block mined! Hash: %s\n", block->hash);
    return SUCCESS;
}

// Transaction validation
ErrorCode validate_transaction(const Transaction *tx) {
    if (!tx) {
        return ERROR_INVALID_PARAM;
    }

    if (strlen(tx->item_id) == 0 || strlen(tx->item_id) >= MAX_ITEM_ID_LENGTH) {
        return ERROR_INVALID_TRANSACTION;
    }
    
    if (strlen(tx->description) >= MAX_DESCRIPTION_LENGTH) {
        return ERROR_INVALID_TRANSACTION;
    }

    return SUCCESS;
}

// Add transaction to block
ErrorCode add_transaction_to_block(Block *block, const Transaction *tx) {
    if (!block || !tx) {
        return ERROR_INVALID_PARAM;
    }

    if (block->num_transactions >= MAX_TRANSACTIONS) {
        return ERROR_BLOCKCHAIN_FULL;
    }

    if (validate_transaction(tx) != SUCCESS) {
        return ERROR_INVALID_TRANSACTION;
    }

    memcpy(&block->transactions[block->num_transactions], tx, sizeof(Transaction));
    block->num_transactions++;
    
    printf("Transaction added: %s\n", tx->item_id);
    return SUCCESS;
}

// Print blockchain function
void print_blockchain(const Blockchain *blockchain) {
    if (!blockchain) {
        printf("Error: Invalid blockchain\n");
        return;
    }

    if (!blockchain->genesis_block) {
        printf("Blockchain is empty\n");
        return;
    }

    const Block *current = blockchain->genesis_block;
    while (current != NULL) {
        printf("\nBlock #%d\n", current->index);
        printf("Timestamp: %s", ctime(&current->timestamp));
        printf("Hash: %s\n", current->hash);
        printf("Previous Hash: %s\n", current->previous_hash);
        printf("Nonce: %d\n", current->nonce);
        printf("Transactions: %d\n", current->num_transactions);
        
        for (int i = 0; i < current->num_transactions; i++) {
            printf("  Transaction %d:\n", i + 1);
            printf("    Item ID: %s\n", current->transactions[i].item_id);
            printf("    Description: %s\n", current->transactions[i].description);
            printf("    Timestamp: %s", ctime(&current->transactions[i].timestamp));
        }
        printf("------------------------\n");
        
        current = current->next_block;
    }
}

// Blockchain initialization
Blockchain* create_blockchain(int difficulty) {
    Blockchain *blockchain = (Blockchain *)malloc(sizeof(Blockchain));
    if (!blockchain) {
        return NULL;
    }
    
    blockchain->genesis_block = NULL;
    blockchain->latest_block = NULL;
    blockchain->total_blocks = 0;
    blockchain->difficulty = difficulty;
    return blockchain;
}

// Memory cleanup
void cleanup_blockchain(Blockchain *blockchain) {
    if (!blockchain) {
        return;
    }

    Block *current = blockchain->genesis_block;
    while (current != NULL) {
        Block *next = current->next_block;
        free(current);
        current = next;
    }

    free(blockchain);
}

// CLI implementation
void run_cli(Blockchain *blockchain) {
    if (!blockchain) {
        printf("Error: Invalid blockchain\n");
        return;
    }

    char buffer[MAX_BUFFER_SIZE];
    int running = 1;

    while (running) {
        printf("\nCommands:\n");
        printf("1. add_transaction\n");
        printf("2. mine_block\n");
        printf("3. print_blockchain\n");
        printf("4. quit\n");
        printf("Enter command number: ");

        if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
            continue;
        }

        int choice;
        if (sscanf(buffer, "%d", &choice) != 1) {
            printf("Invalid input. Please enter a number.\n");
            continue;
        }

        switch (choice) {
            case 1: {
                if (!blockchain->latest_block) {
                    printf("Create a block first using mine_block\n");
                    break;
                }

                Transaction tx;
                tx.timestamp = time(NULL);

                printf("Enter item ID: ");
                if (fgets(buffer, sizeof(buffer), stdin)) {
                    buffer[strcspn(buffer, "\n")] = 0;
                    strncpy(tx.item_id, buffer, MAX_ITEM_ID_LENGTH - 1);
                }

                printf("Enter description: ");
                if (fgets(buffer, sizeof(buffer), stdin)) {
                    buffer[strcspn(buffer, "\n")] = 0;
                    strncpy(tx.description, buffer, MAX_DESCRIPTION_LENGTH - 1);
                }

                // THis is a dummy signature just to try and make the thing simple
                strncpy(tx.signature, "dummy_signature", MAX_SIGNATURE_LENGTH - 1);

                ErrorCode result = add_transaction_to_block(blockchain->latest_block, &tx);
                if (result != SUCCESS) {
                    printf("Failed to add transaction: %d\n", result);
                }
                break;
            }
            case 2: {
                Block *new_block = create_block(blockchain);
                if (!new_block) {
                    printf("Failed to create block\n");
                    break;
                }
                ErrorCode result = mine_block(new_block, blockchain->difficulty);
                if (result != SUCCESS) {
                    printf("Failed to mine block: %d\n", result);
                    free(new_block);
                }
                break;
            }
            case 3:
                print_blockchain(blockchain);
                break;
            case 4:
                running = 0;
                break;
            default:
                printf("Invalid command\n");
        }
    }
}

int main(int argc, char *argv[]) {
    int difficulty = DIFFICULTY;
    
    if (argc > 1) {
        int input_difficulty = atoi(argv[1]);
        if (input_difficulty > 0) {
            difficulty = input_difficulty;
        }
    }
    
    Blockchain *blockchain = create_blockchain(difficulty);
    if (!blockchain) {
        fprintf(stderr, "Failed to create blockchain\n");
        return 1;
    }
    
    run_cli(blockchain);
    cleanup_blockchain(blockchain);
    
    return 0;
}
