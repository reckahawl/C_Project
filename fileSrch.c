#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <regex.h>
#include <pthread.h>
#include <limits.h>

#define MAX_THREADS 8
#define MAX_QUEUE_SIZE 100
#define MAX_PATTERNS 10
#define MAX_FILES 100

typedef struct {
    char name[256];
    char path[1024];
} FileInfo;

typedef struct {
    char file_path[1024];
    const char *patterns[MAX_PATTERNS];
    int pattern_count;
} ThreadData;

typedef struct {
    FileInfo queue[MAX_QUEUE_SIZE];
    int front;
    int rear;
    int size;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} FileQueue;

typedef struct {
    pthread_t threads[MAX_THREADS];
    FileQueue *file_queue;
    const char *patterns[MAX_PATTERNS];
    int pattern_count;
} ThreadPool;

void enqueue(FileQueue *queue, FileInfo file) {
    pthread_mutex_lock(&queue->mutex);

    while (queue->size == MAX_QUEUE_SIZE) {
        pthread_cond_wait(&queue->not_full, &queue->mutex);
    }

    queue->queue[queue->rear] = file;
    queue->rear = (queue->rear + 1) % MAX_QUEUE_SIZE;
    queue->size++;

    pthread_cond_signal(&queue->not_empty);
    pthread_mutex_unlock(&queue->mutex);
}

FileInfo dequeue(FileQueue *queue) {
    pthread_mutex_lock(&queue->mutex);

    while (queue->size == 0) {
        pthread_cond_wait(&queue->not_empty, &queue->mutex);
    }

    FileInfo file = queue->queue[queue->front];
    queue->front = (queue->front + 1) % MAX_QUEUE_SIZE;
    queue->size--;

    pthread_cond_signal(&queue->not_full);
    pthread_mutex_unlock(&queue->mutex);

    return file;
}

void *search_pattern_in_file_thread(void *arg) {
    ThreadPool *pool = (ThreadPool *)arg;
    regex_t regex[MAX_PATTERNS];

    for (int i = 0; i < pool->pattern_count; i++) {
        if (regcomp(&regex[i], pool->patterns[i], REG_NOSUB | REG_EXTENDED) != 0) {
            fprintf(stderr, "Could not compile regex for pattern %s\n", pool->patterns[i]);
            pthread_exit(NULL);
        }
    }

    while (1) {
        FileInfo file_info = dequeue(pool->file_queue);

        FILE *file = fopen(file_info.path, "r");
        if (!file) {
            perror("fopen");
            continue;
        }

        char line[1024];
        int line_number = 0;
        while (fgets(line, sizeof(line), file)) {
            line_number++;
            for (int i = 0; i < pool->pattern_count; i++) {
                if (regexec(&regex[i], line, 0, NULL, 0) == 0) {
                    printf("Match in %s at line %d for pattern '%s': %s", file_info.path, line_number, pool->patterns[i], line);
                }
            }
        }

        fclose(file);
    }

    for (int i = 0; i < pool->pattern_count; i++) {
        regfree(&regex[i]);
    }
    pthread_exit(NULL);
}

void initialize_thread_pool(ThreadPool *pool, const char *patterns[], int pattern_count) {
    pool->file_queue = (FileQueue *)malloc(sizeof(FileQueue));
    pool->file_queue->front = 0;
    pool->file_queue->rear = 0;
    pool->file_queue->size = 0;
    pthread_mutex_init(&pool->file_queue->mutex, NULL);
    pthread_cond_init(&pool->file_queue->not_empty, NULL);
    pthread_cond_init(&pool->file_queue->not_full, NULL);

    pool->pattern_count = pattern_count;
    for (int i = 0; i < pattern_count; i++) {
        pool->patterns[i] = patterns[i];
    }

    for (int i = 0; i < MAX_THREADS; i++) {
        pthread_create(&pool->threads[i], NULL, search_pattern_in_file_thread, pool);
    }
}

void traverse_directory(const char *directory_path, const char *name_patterns[], int name_pattern_count, const char *content_patterns[], int content_pattern_count, int max_depth, int current_depth, ThreadPool *pool, int recursive) {
    if (current_depth > max_depth) {
        return;
    }

    DIR *dp = opendir(directory_path);
    if (dp == NULL) {
        perror("opendir");
        return;
    }

    struct dirent *entry;
    struct stat statbuf;
    regex_t name_regex[MAX_PATTERNS];

    for (int i = 0; i < name_pattern_count; i++) {
        if (regcomp(&name_regex[i], name_patterns[i], REG_NOSUB | REG_EXTENDED) != 0) {
            fprintf(stderr, "Could not compile regex for pattern %s\n", name_patterns[i]);
            closedir(dp);
            return;
        }
    }

    while ((entry = readdir(dp)) != NULL) {
        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", directory_path, entry->d_name);

        if (lstat(path, &statbuf) == -1) {
            perror("lstat");
            continue;
        }

        if (S_ISDIR(statbuf.st_mode)) {
            if (recursive && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                traverse_directory(path, name_patterns, name_pattern_count, content_patterns, content_pattern_count, max_depth, current_depth + 1, pool, recursive);
            }
        } else {
            for (int i = 0; i < name_pattern_count; i++) {
                if (regexec(&name_regex[i], entry->d_name, 0, NULL, 0) == 0) {
                    FileInfo file_info;
                    snprintf(file_info.name, sizeof(file_info.name), "%s", entry->d_name);
                    snprintf(file_info.path, sizeof(file_info.path), "%s", path);

                    enqueue(pool->file_queue, file_info);
                }
            }
        }
    }

    for (int i = 0; i < name_pattern_count; i++) {
        regfree(&name_regex[i]);
    }
    closedir(dp);
}

void list_txt_files(const char *directory_path) {
    DIR *dp = opendir(directory_path);
    if (dp == NULL) {
        perror("opendir");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dp)) != NULL) {
        if (strstr(entry->d_name, ".txt") != NULL) {
            printf("%s/%s\n", directory_path, entry->d_name);
        }
    }

    closedir(dp);
}

void print_usage(const char *program_name) {
    fprintf(stderr, "Usage: %s [-r max_depth] [directory] <name_pattern1> ... <name_patternN> -- <content_pattern1> ... <content_patternM>\n", program_name);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    if (argc == 1) {
        // No parameters provided, list .txt files in the current directory
        list_txt_files(".");
        return 0;
    }

    const char *directory_path = ".";
    const char *name_patterns[MAX_PATTERNS];
    const char *content_patterns[MAX_PATTERNS];
    int name_pattern_count = 0;
    int content_pattern_count = 0;
    int max_depth = INT_MAX;  // No limit by default
    int recursive = 0;

    if (argc < 5) {
        print_usage(argv[0]);
    }

    int arg_index = 1;
    if (strcmp(argv[arg_index], "-r") == 0) {
        recursive = 1;
        max_depth = atoi(argv[arg_index + 1]);
        arg_index += 2;
    }

    if (argc - arg_index < 5) {
        print_usage(argv[0]);
    }

    if (argc - arg_index > 0 && argv[arg_index][0] != '-') {
        directory_path = argv[arg_index];
        arg_index++;
    }

    int pattern_delimiter_found = 0;
    for (int i = arg_index; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            pattern_delimiter_found = 1;
            arg_index = i + 1;
            break;
        }
        name_patterns[name_pattern_count++] = argv[i];
    }

    if (!pattern_delimiter_found || argc - arg_index < 1) {
        print_usage(argv[0]);
    }

    for (int i = arg_index; i < argc; i++) {
        content_patterns[content_pattern_count++] = argv[i];
    }

    ThreadPool pool;
    initialize_thread_pool(&pool, content_patterns, content_pattern_count);

    traverse_directory(directory_path, name_patterns, name_pattern_count, content_patterns, content_pattern_count, max_depth, 0, &pool, recursive);

    for (int i = 0; i < MAX_THREADS; i++) {
        pthread_join(pool.threads[i], NULL);
    }

    // Clean up thread pool
    pthread_mutex_destroy(&pool.file_queue->mutex);
    pthread_cond_destroy(&pool.file_queue->not_empty);
    pthread_cond_destroy(&pool.file_queue->not_full);
    free(pool.file_queue);

    return 0;
}
