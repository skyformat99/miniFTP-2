#include "tunable.h"
#include "parseconf.h"
#include "comm.h"
#include "str.h"
#include <strings.h>

static struct parseconf_bool_setting
{
    const char *p_setting_name;
    int *p_variable;
} parseconf_bool_array[] =
{
    { "pasv_enable", &tunable_pasv_enable },
    { "port_enable", &tunable_port_enable },
    { NULL, NULL }
};

static struct parseconf_uint_setting
{
    const char *p_setting_name;
    unsigned int *p_variable;
} parseconf_uint_array[] =
{
    { "listen_port", &tunable_listen_port },
    { "max_clients", &tunable_max_clients },
    { "max_per_ip", &tunable_max_per_ip },
    { "accept_timeout", &tunable_accept_timeout },
    { "connect_timeout", &tunable_connect_timeout },
    { "idle_session_timeout", &tunable_idle_session_timeout },
    { "data_connection_timeout", &tunable_data_connection_timeout },
    { "local_umask", &tunable_local_umask },
    { "upload_max_rate", &tunable_upload_max_rate },
    { "download_max_rate", &tunable_download_max_rate },
    { NULL, NULL }
};

static struct parseconf_str_setting
{
    const char *p_setting_name;
    const char **p_variable;
} parseconf_str_array[] =
{
    { "listen_address", &tunable_listen_address },
    { NULL, NULL }
};

//加载配置文件
void parseconf_load_file(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (fp == NULL)
    {
        fclose(fp);
        ERR_EXIT("fopen");
    }

    char setline_buf[1024] = {0};
    while(fgets(setline_buf, sizeof(setline_buf), fp) != NULL)
    {
        // 如果是#开头的注释，或者全是空白字符，或者长度为0
        if (setline_buf[0] == '#' 
                || str_all_space(setline_buf)
                || strlen(setline_buf) == 0) 
            continue;

        // 去除\r\n
        str_trim_crlf(setline_buf);
        parseconf_load_setting(setline_buf);
        memset(setline_buf, 0, sizeof(setline_buf));
    }

    fclose(fp);
}

//将配置项加载到相应的变量
void parseconf_load_setting(const char *setting)
{
    // 去除空格
    while(isspace(*setting))
        setting++;

    char key[128] = {0};
    char value[128] = {0};
    str_split(setting, key, value, '=');
    if (strlen(value) == 0) 
    {
        fprintf(stderr, "missing value in config file for:%s\n", key);
        exit(EXIT_FAILURE);
    }

    // 字符串配置项
    {
        const struct parseconf_str_setting *p_str_setting = parseconf_str_array;
        while (p_str_setting->p_setting_name != NULL)
        {
            if (strcmp(key, p_str_setting->p_setting_name) == 0) 
            {
                const char **p_cur_setting = p_str_setting->p_variable;
                if (*p_cur_setting)
                    free((char *)*p_cur_setting);
                *p_cur_setting = strdup(value);
                return ;
            }
            p_str_setting++;
        }
    }
    
    // 开关配置项
    {
        const struct parseconf_bool_setting *p_bool_setting = parseconf_bool_array;
        while (p_bool_setting->p_setting_name != NULL)
        {
            if (strcmp(p_bool_setting->p_setting_name, key) == 0)
            {
                if (strcasecmp(value, "YES") == 0
                        || strcasecmp(value, "TRUE") == 0
                        || strcasecmp(value, "1") == 0)             
                    *(p_bool_setting->p_variable) = 1;
                else if (strcasecmp(value, "NO") == 0
                        || strcasecmp(value, "false") == 0
                        || strcasecmp(value, "0") == 0)
                    *(p_bool_setting->p_variable) = 0;
                else 
                {
                    fprintf(stderr, "missing value in config file for:%s\n", key);
                    exit(EXIT_FAILURE);
                }
                break;
            }
            p_bool_setting++;
        }
    }

    // 无符号整型配置项
    {
        const struct parseconf_uint_setting *p_uint_setting = parseconf_uint_array;
        while (p_uint_setting->p_setting_name != NULL)
        {
            if (strcmp(p_uint_setting->p_setting_name, key) == 0)
            {
                if (value[0] == '0')
                {
                    *(p_uint_setting->p_variable) = str_octal_to_uint(value); 
                }
                else 
                {
                    *(p_uint_setting->p_variable) = atoi(value);
                }
                return ;
            }
            p_uint_setting++;
        }
    }

}


