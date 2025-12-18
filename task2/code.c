#define FUSE_USE_VERSION 31

#include <fuse3/fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <archive.h>
#include <archive_entry.h>
#include <pthread.h>

char* split_string(char* str, const char* delimiter) {
    char* copy = strdup(str);  // Create modifiable copy
    char* token = strtok(copy, delimiter);

    char* result = strdup(token);

    
    free(copy);

    return result;
}

// Структура для хранения информации о файле в tar архиве
typedef struct tar_file {
    char *path;               // Полный путь файла
    size_t size;              // Размер файла
    off_t offset;             // Смещение в архиве
    time_t mtime;             // Время модификации
    mode_t mode;              // Права доступа
    int is_dir;               // Флаг директории
    struct tar_file *next;    // Следующий элемент в списке
} tar_file_t;

// Глобальные переменные
static char *tar_path = NULL;
static tar_file_t *file_list = NULL;
static pthread_mutex_t archive_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct archive *ar = NULL;

// Функция для логирования операций
void log_operation(const char *operation, const char *path, const char *result) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    
    fprintf(stderr, "[%04d-%02d-%02d %02d:%02d:%02d] %s %s: %s\n",
            t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
            t->tm_hour, t->tm_min, t->tm_sec,
            operation, path, result);
    fflush(stderr);
}

// Функция для освобождения списка файлов
static void free_file_list() {
    tar_file_t *current = file_list;
    while (current) {
        tar_file_t *next = current->next;
        free(current->path);
        free(current);
        current = next;
    }
    file_list = NULL;
}

// Функция для добавления файла в список
static void add_file_to_list(const char *path, size_t size, off_t offset, 
                            time_t mtime, mode_t mode, int is_dir) {
    tar_file_t *file = malloc(sizeof(tar_file_t));
    if (!file) {
        log_operation("add_file", path, "memory allocation failed");
        return;
    }
    
    file->path = strdup(path);
    if (!file->path) {
        free(file);
        log_operation("add_file", path, "string duplication failed");
        return;
    }
    
    file->size = size;
    file->offset = offset;
    file->mtime = mtime;
    file->mode = mode;
    file->is_dir = is_dir;
    file->next = file_list;
    file_list = file;
    
    log_operation("add_file", path, "added to cache");
}

// Поиск файла в списке
static tar_file_t *find_file(const char *path) {
    tar_file_t *current = file_list;
    while (current) {
        if (strcmp(current->path, path) == 0) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

// Инициализация и парсинг tar архива
static int parse_tar_archive() {
    struct archive_entry *entry;
    int r;
    
    log_operation("parse_archive", tar_path, "start parsing");
    
    // Создаем объект архива для чтения
    ar = archive_read_new();
    if (!ar) {
        log_operation("parse_archive", tar_path, "failed to create archive object");
        return -1;
    }
    
    // Поддерживаем все форматы и фильтры
    archive_read_support_format_all(ar);
    archive_read_support_filter_all(ar);
    
    // Открываем архив
    r = archive_read_open_filename(ar, tar_path, 10240);
    if (r != ARCHIVE_OK) {
        log_operation("parse_archive", tar_path, archive_error_string(ar));
        archive_read_free(ar);
        ar = NULL;
        return -1;
    }
    
    off_t current_offset = 0;
    int file_count = 0;
    
    // Читаем все записи в архиве
    while (archive_read_next_header(ar, &entry) == ARCHIVE_OK) {
        const char *entry_path = archive_entry_pathname(entry);
        mode_t mode = archive_entry_mode(entry);
        time_t mtime = archive_entry_mtime(entry);
        size_t size = archive_entry_size(entry);
        int is_dir = S_ISDIR(mode);
        
        // Добавляем ведущий слеш для корня
        char full_path[4096];
        snprintf(full_path, sizeof(full_path), "/%s", entry_path);
        
        // Сохраняем информацию о файле
        add_file_to_list(full_path, size, current_offset, mtime, mode, is_dir);
        file_count++;
        
        // Пропускаем данные файла
        if (!is_dir) {
            archive_read_data_skip(ar);
        }
        
        // Обновляем смещение (упрощенно - в реальности нужно точное вычисление)
        current_offset += 512; // Блок заголовка
        if (!is_dir) {
            current_offset += ((size + 511) / 512) * 512; // Блоки данных
        }
    }
    
    // Закрываем архив (но не освобождаем)
    archive_read_close(ar);
    
    // Добавляем корневую директорию если ее нет
    if (!find_file("/")) {
        add_file_to_list("/", 0, 0, time(NULL), S_IFDIR | 0555, 1);
        file_count++;
    }
    
    char result[256];
    snprintf(result, sizeof(result), "parsed %d files", file_count);
    log_operation("parse_archive", tar_path, result);
    
    return 0;
}

// Получение атрибутов файла
// Улучшенная версия функции getattr
static int tarfs_getattr(const char *path, struct stat *stbuf,
                         struct fuse_file_info *fi) {
    (void) fi;
    
    memset(stbuf, 0, sizeof(struct stat));
    
    pthread_mutex_lock(&archive_mutex);
    
    // Пробуем разные варианты пути
    tar_file_t *file = find_file(path);
    
    if (!file) {
        // Пробуем с завершающим слешем
        char path_with_slash[4096];
        snprintf(path_with_slash, sizeof(path_with_slash), "%s/", path);
        file = find_file(path_with_slash);
    }
    
    if (!file) {
        // Пробуем без начального слеша (для сравнения)
        if (path[0] == '/' && strlen(path) > 1) {
            file = find_file(path + 1);
        }
    }
    
    if (!file) {
        // Проверяем, может ли это быть директорией
        // Ищем файлы, которые начинаются с path + "/"
        char check_prefix[4096];
        if (strcmp(path, "/") == 0) {
            strcpy(check_prefix, "/");
        } else {
            snprintf(check_prefix, sizeof(check_prefix), "%s/", path);
        }
        
        tar_file_t *current = file_list;
        int has_children = 0;
        while (current) {
            if (strncmp(current->path, check_prefix, strlen(check_prefix)) == 0) {
                has_children = 1;
                break;
            }
            current = current->next;
        }
        
        if (has_children) {
            // Это неявная директория
            stbuf->st_mode = S_IFDIR | 0555;
            stbuf->st_nlink = 2;
            stbuf->st_uid = getuid();
            stbuf->st_gid = getgid();
            stbuf->st_atime = time(NULL);
            stbuf->st_mtime = time(NULL);
            stbuf->st_ctime = time(NULL);
            
            pthread_mutex_unlock(&archive_mutex);
            
            log_operation("getattr", path, "OK (implicit directory with children)");
            return 0;
        }
        
        pthread_mutex_unlock(&archive_mutex);
        log_operation("getattr", path, "not found");
        return -ENOENT;
    }
    
    if (file->is_dir) {
        stbuf->st_mode = S_IFDIR | 0555;
        stbuf->st_nlink = 2;
    } else {
        stbuf->st_mode = S_IFREG | 0444;
        stbuf->st_nlink = 1;
        stbuf->st_size = file->size;
    }
    
    stbuf->st_uid = getuid();
    stbuf->st_gid = getgid();
    stbuf->st_atime = file->mtime;
    stbuf->st_mtime = file->mtime;
    stbuf->st_ctime = file->mtime;
    
    pthread_mutex_unlock(&archive_mutex);
    
    char result[256];
    snprintf(result, sizeof(result), "OK (size=%ld, mode=%o, is_dir=%d)", 
             (long)stbuf->st_size, stbuf->st_mode, file->is_dir);
    log_operation("getattr", path, result);
    
    return 0;
}

// Чтение содержимого директории
static int tarfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                         off_t offset, struct fuse_file_info *fi,
                         enum fuse_readdir_flags flags) {
    (void) offset;
    (void) fi;
    (void) flags;
    
    log_operation("readdir", path, "start");
    
    // Всегда добавляем . и ..
    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);
    
    pthread_mutex_lock(&archive_mutex);
    
    tar_file_t *current = file_list;
    int entry_count = 2;
    
    // Нормализуем путь запроса - добавляем / в конец если нужно
    char normalized_path[1024];
    snprintf(normalized_path, sizeof(normalized_path), "%s", path);
    
    size_t path_len = strlen(normalized_path);
    if (path_len > 1 && normalized_path[path_len - 1] != '/') {
        strcat(normalized_path, "/");
        path_len++;
    }
    
    // Для хранения уже добавленных имен
    char *added_names[1000];
    int added_count = 0;
    
    while (current) {
        // Проверяем, относится ли этот файл к запрашиваемой директории
        int is_in_dir = 0;
        char *relative_part = NULL;
        
        // Сравниваем пути
        if (strncmp(current->path, normalized_path, path_len) == 0) {
            // Путь начинается с запрашиваемой директории
            relative_part = (char *)current->path + path_len;
            is_in_dir = 1;
        } else if (strcmp(normalized_path, "/") == 0 && current->path[0] == '/') {
            // Особый случай: корневая директория
            relative_part = (char *)current->path + 1; // пропускаем первый /
            is_in_dir = 1;
        }
        
        if (is_in_dir && relative_part && relative_part[0] != '\0') {
            // Находим первое вхождение / в relative_part
            char *slash_pos = strchr(relative_part, '/');
            char entry_name[256];
            
            if (slash_pos) {
                // Есть поддиректория - берем первую часть
                size_t len = slash_pos - relative_part;
                if (len > 0 && len < sizeof(entry_name)) {
                    strncpy(entry_name, relative_part, len);
                    entry_name[len] = '\0';
                } else {
                    current = current->next;
                    continue;
                }
            } else {
                // Нет / - это файл в текущей директории
                if (strlen(relative_part) > 0 && strlen(relative_part) < sizeof(entry_name)) {
                    strcpy(entry_name, relative_part);
                } else {
                    current = current->next;
                    continue;
                }
            }
            
            // Проверяем, не добавляли ли мы уже это имя
            int already_added = 0;
            for (int i = 0; i < added_count; i++) {
                if (strcmp(added_names[i], entry_name) == 0) {
                    already_added = 1;
                    break;
                }
            }
            
            if (!already_added && added_count < 1000) {
                // Сохраняем имя
                added_names[added_count] = strdup(entry_name);
                if (!added_names[added_count]) {
                    current = current->next;
                    continue;
                }
                added_count++;
                
                // Создаем полный путь для проверки типа
                char full_entry_path[1024];
                if (strcmp(path, "/") == 0) {
                    snprintf(full_entry_path, sizeof(full_entry_path), "/%s", entry_name);
                } else {
                    snprintf(full_entry_path, sizeof(full_entry_path), "%s/%s", path, entry_name);
                }
                
                // Ищем запись в списке
                tar_file_t *entry = find_file(full_entry_path);
                
                struct stat st;
                memset(&st, 0, sizeof(st));
                
                if (entry && entry->is_dir) {
                    // Это директория
                    st.st_mode = S_IFDIR | 0555;
                    st.st_nlink = 2;
                    log_operation("readdir_add", entry_name, "dir");
                } else {
                    // Это файл или мы не нашли запись (значит это промежуточная директория)
                    st.st_mode = S_IFREG | 0444;
                    st.st_nlink = 1;
                    if (entry) {
                        st.st_size = entry->size;
                    }
                    log_operation("readdir_add", entry_name, "file");
                }
                
                filler(buf, entry_name, &st, 0, 0);
                entry_count++;
            }
        }
        current = current->next;
    }
    
    // Освобождаем память
    for (int i = 0; i < added_count; i++) {
        free(added_names[i]);
    }
    
    pthread_mutex_unlock(&archive_mutex);
    
    char result[256];
    snprintf(result, sizeof(result), "OK (%d entries)", entry_count - 2);
    log_operation("readdir", path, result);
    
    return 0;
}

// Открытие файла
static int tarfs_open(const char *path, struct fuse_file_info *fi) {
    log_operation("open", path, "attempt");
    
    pthread_mutex_lock(&archive_mutex);
    tar_file_t *file = find_file(path);
    
    if (!file) {
        pthread_mutex_unlock(&archive_mutex);
        log_operation("open", path, "not found");
        return -ENOENT;
    }
    
    if (file->is_dir) {
        pthread_mutex_unlock(&archive_mutex);
        log_operation("open", path, "is directory");
        return -EISDIR;
    }
    
    // Проверяем режим доступа (только чтение)
    if ((fi->flags & O_ACCMODE) != O_RDONLY) {
        pthread_mutex_unlock(&archive_mutex);
        log_operation("open", path, "write attempt denied");
        return -EACCES;
    }
    
    pthread_mutex_unlock(&archive_mutex);
    
    char result[256];
    snprintf(result, sizeof(result), "OK (size=%ld)", (long)file->size);
    log_operation("open", path, result);
    
    return 0;
}

// Чтение из файла
static int tarfs_read(const char *path, char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi) {
    (void) fi;
    
    char log_msg[512];
    snprintf(log_msg, sizeof(log_msg), "offset=%ld, size=%ld", (long)offset, (long)size);
    log_operation("read", path, log_msg);
    
    pthread_mutex_lock(&archive_mutex);
    
    tar_file_t *file = find_file(path);
    if (!file) {
        pthread_mutex_unlock(&archive_mutex);
        log_operation("read", path, "not found");
        return -ENOENT;
    }
    
    if (file->is_dir) {
        pthread_mutex_unlock(&archive_mutex);
        log_operation("read", path, "is directory");
        return -EISDIR;
    }
    
    // Проверяем границы
    if (offset >= file->size) {
        pthread_mutex_unlock(&archive_mutex);
        log_operation("read", path, "offset beyond file size");
        return 0;
    }
    
    if (offset + size > file->size) {
        size = file->size - offset;
        snprintf(log_msg, sizeof(log_msg), "adjusted size to %ld", (long)size);
        log_operation("read", path, log_msg);
    }
    
    // Читаем данные из архива
    struct archive *a = archive_read_new();
    archive_read_support_format_all(a);
    archive_read_support_filter_all(a);
    
    int r = archive_read_open_filename(a, tar_path, 10240);
    if (r != ARCHIVE_OK) {
        pthread_mutex_unlock(&archive_mutex);
        log_operation("read", path, archive_error_string(a));
        archive_read_free(a);
        return -EIO;
    }
    
    struct archive_entry *entry;
    ssize_t bytes_read = 0;
    
    // Ищем нужный файл в архиве
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        const char *entry_path = archive_entry_pathname(entry);
        char full_path[4096];
        snprintf(full_path, sizeof(full_path), "/%s", entry_path);
        
        if (strcmp(full_path, path) == 0) {
            log_operation("read_found", path, "found in archive");
            
            // Пропускаем данные до нужного смещения
            if (offset > 0) {
                char dummy[4096];
                off_t to_skip = offset;
                while (to_skip > 0) {
                    ssize_t skip_size = to_skip > sizeof(dummy) ? sizeof(dummy) : to_skip;
                    ssize_t skipped = archive_read_data(a, dummy, skip_size);
                    if (skipped <= 0) {
                        log_operation("read", path, "skip failed");
                        break;
                    }
                    to_skip -= skipped;
                }
            }
            
            // Читаем запрошенные данные
            bytes_read = archive_read_data(a, buf, size);
            break;
        } else {
            // Пропускаем этот файл
            archive_read_data_skip(a);
        }
    }
    
    archive_read_close(a);
    archive_read_free(a);
    
    pthread_mutex_unlock(&archive_mutex);
    
    if (bytes_read < 0) {
        log_operation("read", path, "read failed");
        return -EIO;
    }
    
    snprintf(log_msg, sizeof(log_msg), "OK (%ld bytes read)", (long)bytes_read);
    log_operation("read", path, log_msg);
    
    return bytes_read;
}

// Инициализация файловой системы
static void* tarfs_init(struct fuse_conn_info *conn,
                       struct fuse_config *cfg) {
    (void) conn;
    (void) cfg;
    
    log_operation("init", "", "tar filesystem initialized");
    log_operation("init", tar_path, "using tar archive");
    
    // Выводим информацию о файлах при старте
    pthread_mutex_lock(&archive_mutex);
    tar_file_t *current = file_list;
    int total_files = 0, total_dirs = 0;
    
    while (current) {
        if (current->is_dir) total_dirs++;
        else total_files++;
        current = current->next;
    }
    pthread_mutex_unlock(&archive_mutex);
    
    fprintf(stderr, "Archive contains: %d files, %d directories\n", total_files, total_dirs);
    
    return NULL;
}

// Деинициализация файловой системы
static void tarfs_destroy(void *private_data) {
    log_operation("destroy", "", "tar filesystem destroyed");
    pthread_mutex_destroy(&archive_mutex);
}

// Операции файловой системы
static struct fuse_operations tarfs_oper = {
    .getattr    = tarfs_getattr,
    .readdir    = tarfs_readdir,
    .open       = tarfs_open,
    .read       = tarfs_read,
    .init       = tarfs_init,
    .destroy    = tarfs_destroy,
};

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <tar_file> <mount_point> [fuse_options]\n", argv[0]);
        fprintf(stderr, "Example: %s archive.tar /mnt/tar -f -d\n", argv[0]);
        return 1;
    }
    
    // Проверяем существование tar файла
    tar_path = realpath(argv[1], NULL);
    if (!tar_path) {
        fprintf(stderr, "Error: Cannot resolve path for '%s'\n", argv[1]);
        return 1;
    }
    
    if (access(tar_path, R_OK) != 0) {
        fprintf(stderr, "Error: Cannot read tar file '%s'\n", tar_path);
        free(tar_path);
        return 1;
    }
    
    fprintf(stderr, "Initializing tar filesystem for: %s\n", tar_path);
    
    // Парсим tar архив
    if (parse_tar_archive() != 0) {
        fprintf(stderr, "Error: Failed to parse tar archive\n");
        free(tar_path);
        return 1;
    }
    
    printf("Successfully parsed tar archive: %s\n", tar_path);
    printf("Mounting to: %s\n", argv[2]);
    printf("Filesystem is read-only\n");
    printf("Logs will be written to stderr\n");
    
    // Готовим аргументы для FUSE
    int fuse_argc = argc - 1;
    char **fuse_argv = malloc((fuse_argc + 1) * sizeof(char *));
    if (!fuse_argv) {
        free(tar_path);
        free_file_list();
        if (ar) archive_read_free(ar);
        return 1;
    }
    
    // Первый аргумент - имя программы
    fuse_argv[0] = argv[0];
    
    // Точка монтирования теперь на месте второго аргумента
    fuse_argv[1] = argv[2];
    
    // Копируем остальные аргументы (fuse опции)
    for (int i = 2; i < fuse_argc; i++) {
        fuse_argv[i] = argv[i + 1];
    }
    
    // Запускаем FUSE
    int ret = fuse_main(fuse_argc, fuse_argv, &tarfs_oper, NULL);
    
    // Очистка
    free(fuse_argv);
    free(tar_path);
    free_file_list();
    if (ar) archive_read_free(ar);
    pthread_mutex_destroy(&archive_mutex);
    
    fprintf(stderr, "Filesystem unmounted\n");
    
    return ret;
}