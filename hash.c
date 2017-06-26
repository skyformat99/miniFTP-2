#include "hash.h"
#include "comm.h"
#include <assert.h>

typedef struct hash_node
{
    void *key;
    void *value;
    struct hash_node *prev;
    struct hash_node *next;
} hash_node_t;

struct hash
{
    unsigned int buckets;
    hashfunc_t hash_func;
    hash_node_t **nodes;
};

 /*获取桶地址*/
hash_node_t** hash_get_bucket(hash_t *hash, void *key);

/*根据 key 获取哈希表中的一个节点*/
hash_node_t* hash_get_node_by_key(hash_t *hash, void *key, unsigned int key_size);

// 创建哈希表
hash_t* hash_alloc(unsigned int buckets, hashfunc_t hash_func)
{
    hash_t *hash = (hash_t *)malloc(sizeof(hash_t));
    hash->buckets = buckets;
    hash->hash_func = hash_func;
    hash->nodes = (hash_node_t **)malloc(sizeof(hash_node_t *) * buckets);   
    memset(hash->nodes, 0, sizeof(hash_node_t *)*buckets);

    return hash;
}

// 在哈希表中查找，返回value
void* hash_lookup_entry(hash_t *hash, void* key, unsigned int key_size)
{
    hash_node_t *node;
    if ((node = hash_get_node_by_key(hash, key, key_size)) == NULL)
        return NULL;
    return node->value;
}

// 往哈希表中添加一项
void hash_add_entry(hash_t *hash, void *key, unsigned int key_size, void *value, unsigned int value_size)
{
    if (hash_lookup_entry(hash, key, key_size))
        return ;
    hash_node_t *node = (hash_node_t *)malloc(sizeof(hash_node_t));
    node->prev = NULL;
    node->next = NULL;
    
    node->key = malloc(key_size);
    memcpy(node->key, key, key_size);
    node->value = malloc(value_size);
    memcpy(node->value, value, value_size);

    hash_node_t **bucket = hash_get_bucket(hash, key);
    if (*bucket == NULL)
        *bucket = node;
    else
    {
        node->next = *bucket;
        (*bucket)->prev = node;
        *bucket = node;
    }
}

// 从哈希表中删除一项
void hash_free_entry(hash_t *hash, void *key, unsigned int key_size)
{
    hash_node_t *node = hash_get_node_by_key(hash, key, key_size);
    if (node != NULL)
    {
        free(node->key); 
        free(node->value); 

        if (node->prev)
        {
            node->prev->next = node->next;
        }
        else
        {
            hash_node_t **bucket = hash_get_bucket(hash, key); 
            *bucket = node->next;
        }
        if (node->next)
            node->next->prev = node->prev;
        free(node);
    }
}

 /*获取桶地址*/
hash_node_t** hash_get_bucket(hash_t *hash, void *key)
{
    unsigned int buckets = hash->hash_func(hash->buckets, key); 
    assert(buckets <= hash->buckets);
    return &hash->nodes[buckets];
}

/*根据 key 获取哈希表中的一个节点*/
hash_node_t* hash_get_node_by_key(hash_t *hash, void *key, unsigned int key_size)
{
    hash_node_t **bucket = hash_get_bucket(hash, key);
    hash_node_t *node = *bucket;
    
    while(node != NULL && memcmp(key, node->key, key_size) != 0)
        node = node->next;

    return node;
}

