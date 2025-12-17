#define FUSE_USE_VERSION 31

#include <fuse3/fuse.h>  // Изменено для FUSE3
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

static char *base_path = NULL;

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

// Полный путь в базовой директории
static char* get_full_path(const char *path) {
    char *full_path = malloc(strlen(base_path) + strlen(path) + 1);
    if (!full_path) return NULL;
    
    strcpy(full_path, base_path);
    strcat(full_path, path);
    return full_path;
}

// Получение атрибутов файла/директории
static int myfs_getattr(const char *path, struct stat *stbuf,
                        struct fuse_file_info *fi) {  // Добавлен параметр fi
    (void) fi;  // Не используется, но нужен для совместимости с FUSE3
    
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
                        enum fuse_readdir_flags flags) {  // Добавлен параметр flags
    (void) offset;
    (void) fi;
    (void) flags;
    
    char *full_path = get_full_path(path);
    if (!full_path) {
        log_operation("readdir", path, "ERROR: memory allocation failed");
        return -ENOMEM;
    }
    
    DIR *dp = opendir(full_path);
    if (dp == NULL) {
        log_operation("readdir", path, strerror(errno));
        free(full_path);
        return -errno;
    }
    
    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        
        // В FUSE3 изменился прототип filler функции
        if (filler(buf, de->d_name, &st, 0, 0)) break;
    }
    
    closedir(dp);
    log_operation("readdir", path, "OK");
    free(full_path);
    return 0;
}

// Открытие файла
static int myfs_open(const char *path, struct fuse_file_info *fi) {
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
    log_operation("open", path, "OK");
    free(full_path);
    return 0;
}

// Чтение из файла
static int myfs_read(const char *path, char *buf, size_t size, off_t offset,
                     struct fuse_file_info *fi) {
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
    log_operation("read", path, "OK");
    free(full_path);
    return res;
}

// Запись в файла
static int myfs_write(const char *path, const char *buf, size_t size,
                      off_t offset, struct fuse_file_info *fi) {
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
    log_operation("write", path, "OK");
    free(full_path);
    return res;
}

// Создание файла
static int myfs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
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
    log_operation("create", path, "OK");
    free(full_path);
    return 0;
}

// Удаление файла
static int myfs_unlink(const char *path) {
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
    
    log_operation("rmdir", path, "OK");
    free(full_path);
    return 0;
}

// Инициализация файловой системы
static void* myfs_init(struct fuse_conn_info *conn,
                       struct fuse_config *cfg) {  // Добавлен параметр cfg
    (void) conn;
    (void) cfg;
    log_operation("init", "", "Filesystem initialized");
    return NULL;
}

// Деинициализация файловой системы
static void myfs_destroy(void *private_data) {
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
    
    // Запускаем FUSE
    int ret = fuse_main(fuse_argc, fuse_argv, &myfs_oper, NULL);
    
    free(base_path);
    return ret;
}