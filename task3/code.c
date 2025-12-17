#define FUSE_USE_VERSION 31

#include <fuse3/fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>

static char *base_path = NULL;

// Структура для хранения статистики
struct fs_stats {
    int reads;
    int writes;
    int opens;
    int creates;
    int unlinks;
    int mkdirs;
    int rmdirs;
    long long bytes_read;
    long long bytes_written;
    pthread_mutex_t lock; // Мьютекс для потокобезопасности
};

static struct fs_stats stats;

// Функция для логирования операций
void log_operation(const char *operation, const char *path, const char *result) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    
    fprintf(stderr, "[%04d-%02d-%02d %02d:%02d:%02d] %s: %s (%s)\n",
            t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
            t->tm_hour, t->tm_min, t->tm_sec,
            operation, path, result);
    fflush(stderr);
}

// Обновление статистики
void update_stat(const char *operation, long long bytes) {
    pthread_mutex_lock(&stats.lock);
    
    if (strcmp(operation, "read") == 0) {
        stats.reads++;
        if (bytes > 0) stats.bytes_read += bytes;
    } else if (strcmp(operation, "write") == 0) {
        stats.writes++;
        if (bytes > 0) stats.bytes_written += bytes;
    } else if (strcmp(operation, "open") == 0) {
        stats.opens++;
    } else if (strcmp(operation, "create") == 0) {
        stats.creates++;
    } else if (strcmp(operation, "unlink") == 0) {
        stats.unlinks++;
    } else if (strcmp(operation, "mkdir") == 0) {
        stats.mkdirs++;
    } else if (strcmp(operation, "rmdir") == 0) {
        stats.rmdirs++;
    }
    
    pthread_mutex_unlock(&stats.lock);
}

// Генерация содержимого файла статистики
char* generate_stats_content() {
    pthread_mutex_lock(&stats.lock);
    
    // Вычисляем необходимый размер буфера
    int size = snprintf(NULL, 0,
        "reads: %d\n"
        "writes: %d\n"
        "opens: %d\n"
        "creates: %d\n"
        "unlinks: %d\n"
        "mkdirs: %d\n"
        "rmdirs: %d\n"
        "bytes_read: %lld\n"
        "bytes_written: %lld\n",
        stats.reads, stats.writes, stats.opens, stats.creates,
        stats.unlinks, stats.mkdirs, stats.rmdirs,
        stats.bytes_read, stats.bytes_written);
    
    char *content = malloc(size + 1);
    if (content) {
        sprintf(content,
            "reads: %d\n"
            "writes: %d\n"
            "opens: %d\n"
            "creates: %d\n"
            "unlinks: %d\n"
            "mkdirs: %d\n"
            "rmdirs: %d\n"
            "bytes_read: %lld\n"
            "bytes_written: %lld\n",
            stats.reads, stats.writes, stats.opens, stats.creates,
            stats.unlinks, stats.mkdirs, stats.rmdirs,
            stats.bytes_read, stats.bytes_written);
    }
    
    pthread_mutex_unlock(&stats.lock);
    return content;
}

// Полный путь в базовой директории
static char* get_full_path(const char *path) {
    // Обработка виртуального файла .stats
    if (strcmp(path, "/.stats") == 0) {
        return NULL;
    }
    
    char *full_path = malloc(strlen(base_path) + strlen(path) + 1);
    if (!full_path) return NULL;
    
    strcpy(full_path, base_path);
    strcat(full_path, path);
    return full_path;
}

// Получение атрибутов файла/директории
static int myfs_getattr(const char *path, struct stat *stbuf,
                        struct fuse_file_info *fi) {
    (void) fi;
    
    // Обработка виртуального файла .stats
    if (strcmp(path, "/.stats") == 0) {
        memset(stbuf, 0, sizeof(struct stat));
        stbuf->st_mode = S_IFREG | 0444; // Регулярный файл, только чтение
        stbuf->st_nlink = 1;
         // КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: вычисляем реальный размер
        char *stats_content = generate_stats_content();
        if (stats_content) {
            stbuf->st_size = strlen(stats_content); // Правильный размер
            free(stats_content);
        } else {
            stbuf->st_size = 0; // На случай ошибки
        }
        stbuf->st_uid = getuid();
        stbuf->st_gid = getgid();
        stbuf->st_atime = stbuf->st_mtime = stbuf->st_ctime = time(NULL);
        log_operation("getattr", path, "VIRTUAL");
        return 0;
    }
    
    char *full_path = get_full_path(path);
    if (!full_path) {
        log_operation("getattr", path, "ERROR: memory allocation failed");
        return -ENOMEM;
    }
    
    int res = lstat(full_path, stbuf);
    if (res == -1) {
        log_operation("getattr", path, strerror(errno));
        free(full_path);
        return -errno;
    }
    
    log_operation("getattr", path, "OK");
    free(full_path);
    return 0;
}

// Чтение содержимого директории
static int myfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                        off_t offset, struct fuse_file_info *fi,
                        enum fuse_readdir_flags flags) {
    (void) offset;
    (void) fi;
    (void) flags;
    
    char *full_path = get_full_path(path);
    if (!full_path) {
        // Это корневая директория, добавим .stats
        filler(buf, ".", NULL, 0, 0);
        filler(buf, "..", NULL, 0, 0);
        filler(buf, ".stats", NULL, 0, 0);
        log_operation("readdir", path, "OK (with .stats)");
        return 0;
    }
    
    DIR *dp = opendir(full_path);
    if (dp == NULL) {
        log_operation("readdir", path, strerror(errno));
        free(full_path);
        return -errno;
    }
    
    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);
    
    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        
        if (filler(buf, de->d_name, &st, 0, 0)) break;
    }
    
    // Если это корневая директория, добавляем .stats
    if (strcmp(path, "/") == 0) {
        filler(buf, ".stats", NULL, 0, 0);
    }
    
    closedir(dp);
    log_operation("readdir", path, "OK");
    free(full_path);
    return 0;
}

// Открытие файла
static int myfs_open(const char *path, struct fuse_file_info *fi) {
    // Обработка виртуального файла .stats
    if (strcmp(path, "/.stats") == 0) {
        if ((fi->flags & O_ACCMODE) != O_RDONLY) {
            return -EACCES; // Только чтение
        }
        update_stat("open", 0);
        log_operation("open", path, "VIRTUAL");
        return 0;
    }
    
    char *full_path = get_full_path(path);
    if (!full_path) {
        log_operation("open", path, "ERROR: memory allocation failed");
        return -ENOMEM;
    }
    
    int res = open(full_path, fi->flags);
    if (res == -1) {
        log_operation("open", path, strerror(errno));
        free(full_path);
        return -errno;
    }
    
    close(res);
    update_stat("open", 0);
    log_operation("open", path, "OK");
    free(full_path);
    return 0;
}

// Чтение из файла
static int myfs_read(const char *path, char *buf, size_t size, off_t offset,
                     struct fuse_file_info *fi) {
    // Обработка виртуального файла .stats
    if (strcmp(path, "/.stats") == 0) {
        char *stats_content = generate_stats_content();
        if (!stats_content) {
            return -ENOMEM;
        }
        
        size_t content_len = strlen(stats_content);
        
        // Проверяем offset
        if (offset >= content_len) {
            free(stats_content);
            return 0;
        }
        
        // Копируем данные в буфер
        size_t to_copy = size;
        if (offset + to_copy > content_len) {
            to_copy = content_len - offset;
        }
        
        memcpy(buf, stats_content + offset, to_copy);
        update_stat("read", to_copy);
        log_operation("read", path, "VIRTUAL");
        
        free(stats_content);
        return to_copy;
    }
    
    char *full_path = get_full_path(path);
    if (!full_path) {
        log_operation("read", path, "ERROR: memory allocation failed");
        return -ENOMEM;
    }
    
    int fd = open(full_path, O_RDONLY);
    if (fd == -1) {
        log_operation("read", path, strerror(errno));
        free(full_path);
        return -errno;
    }
    
    int res = pread(fd, buf, size, offset);
    if (res == -1) {
        log_operation("read", path, strerror(errno));
        close(fd);
        free(full_path);
        return -errno;
    }
    
    close(fd);
    update_stat("read", res);
    log_operation("read", path, "OK");
    free(full_path);
    return res;
}

// Запись в файл
static int myfs_write(const char *path, const char *buf, size_t size,
                      off_t offset, struct fuse_file_info *fi) {
    // Виртуальный файл .stats только для чтения
    if (strcmp(path, "/.stats") == 0) {
        return -EACCES;
    }
    
    char *full_path = get_full_path(path);
    if (!full_path) {
        log_operation("write", path, "ERROR: memory allocation failed");
        return -ENOMEM;
    }
    
    int fd = open(full_path, O_WRONLY);
    if (fd == -1) {
        log_operation("write", path, strerror(errno));
        free(full_path);
        return -errno;
    }
    
    int res = pwrite(fd, buf, size, offset);
    if (res == -1) {
        log_operation("write", path, strerror(errno));
        close(fd);
        free(full_path);
        return -errno;
    }
    
    close(fd);
    update_stat("write", res);
    log_operation("write", path, "OK");
    free(full_path);
    return res;
}

// Создание файла
static int myfs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    // Нельзя создавать .stats
    if (strcmp(path, "/.stats") == 0) {
        return -EACCES;
    }
    
    char *full_path = get_full_path(path);
    if (!full_path) {
        log_operation("create", path, "ERROR: memory allocation failed");
        return -ENOMEM;
    }
    
    int fd = creat(full_path, mode);
    if (fd == -1) {
        log_operation("create", path, strerror(errno));
        free(full_path);
        return -errno;
    }
    
    fi->fh = fd;
    update_stat("create", 0);
    log_operation("create", path, "OK");
    free(full_path);
    return 0;
}

// Удаление файла
static int myfs_unlink(const char *path) {
    // Нельзя удалять .stats
    if (strcmp(path, "/.stats") == 0) {
        return -EACCES;
    }
    
    char *full_path = get_full_path(path);
    if (!full_path) {
        log_operation("unlink", path, "ERROR: memory allocation failed");
        return -ENOMEM;
    }
    
    int res = unlink(full_path);
    if (res == -1) {
        log_operation("unlink", path, strerror(errno));
        free(full_path);
        return -errno;
    }
    
    update_stat("unlink", 0);
    log_operation("unlink", path, "OK");
    free(full_path);
    return 0;
}

// Создание директории
static int myfs_mkdir(const char *path, mode_t mode) {
    char *full_path = get_full_path(path);
    if (!full_path) {
        log_operation("mkdir", path, "ERROR: memory allocation failed");
        return -ENOMEM;
    }
    
    int res = mkdir(full_path, mode);
    if (res == -1) {
        log_operation("mkdir", path, strerror(errno));
        free(full_path);
        return -errno;
    }
    
    update_stat("mkdir", 0);
    log_operation("mkdir", path, "OK");
    free(full_path);
    return 0;
}

// Удаление директории
static int myfs_rmdir(const char *path) {
    char *full_path = get_full_path(path);
    if (!full_path) {
        log_operation("rmdir", path, "ERROR: memory allocation failed");
        return -ENOMEM;
    }
    
    int res = rmdir(full_path);
    if (res == -1) {
        log_operation("rmdir", path, strerror(errno));
        free(full_path);
        return -errno;
    }
    
    update_stat("rmdir", 0);
    log_operation("rmdir", path, "OK");
    free(full_path);
    return 0;
}

// Инициализация файловой системы
static void* myfs_init(struct fuse_conn_info *conn,
                       struct fuse_config *cfg) {
    (void) conn;
    (void) cfg;
    
    // Инициализация статистики
    memset(&stats, 0, sizeof(stats));
    pthread_mutex_init(&stats.lock, NULL);
    
    log_operation("init", "", "Filesystem initialized");
    return NULL;
}

// Деинициализация файловой системы
static void myfs_destroy(void *private_data) {
    pthread_mutex_destroy(&stats.lock);
    log_operation("destroy", "", "Filesystem destroyed");
}

// Операции файловой системы
static struct fuse_operations myfs_oper = {
    .getattr    = myfs_getattr,
    .readdir    = myfs_readdir,
    .open       = myfs_open,
    .read       = myfs_read,
    .write      = myfs_write,
    .create     = myfs_create,
    .unlink     = myfs_unlink,
    .mkdir      = myfs_mkdir,
    .rmdir      = myfs_rmdir,
    .init       = myfs_init,
    .destroy    = myfs_destroy,
};

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <source_dir> <mount_point> [fuse_options]\n", argv[0]);
        return 1;
    }
    
    // Сохраняем базовый путь
    base_path = realpath(argv[1], NULL);
    if (!base_path) {
        fprintf(stderr, "Error: Invalid source directory '%s'\n", argv[1]);
        return 1;
    }
    
    // Проверяем существование базовой директории
    struct stat st;
    if (stat(base_path, &st) == -1 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "Error: Source directory '%s' does not exist or is not a directory\n", base_path);
        free(base_path);
        return 1;
    }
    
    // Добавляем завершающий слэш если нужно
    if (base_path[strlen(base_path) - 1] != '/') {
        char *tmp = realloc(base_path, strlen(base_path) + 2);
        if (!tmp) {
            free(base_path);
            return 1;
        }
        base_path = tmp;
        strcat(base_path, "/");
    }
    
    int fuse_argc = 0;
    char *fuse_argv[argc + 3];

    // Программа
    fuse_argv[fuse_argc++] = argv[0];
    
    // Точка монтирования
    fuse_argv[fuse_argc++] = argv[2];
    
    // Добавляем опцию -f для foreground режима
    fuse_argv[fuse_argc++] = "-f";
    
    // Добавляем остальные аргументы пользователя (если есть)
    for (int i = 3; i < argc; i++) {
        fuse_argv[fuse_argc++] = argv[i];
    }
    
    printf("Mounting %s to %s\n", base_path, argv[2]);
    printf("All operations will be logged to stderr\n");
    printf("Statistics file available at: %s/.stats\n", argv[2]);
    
    // Запускаем FUSE
    int ret = fuse_main(fuse_argc, fuse_argv, &myfs_oper, NULL);
    
    free(base_path);
    return ret;
}