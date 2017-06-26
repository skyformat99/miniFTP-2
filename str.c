#include "str.h"
#include "comm.h"

// 去除\r\n
void str_trim_crlf(char *str)
{
    // p指向str的最后一个字符
    char *p = p = &str[strlen(str)-1];
    while(*p == '\r' || *p == '\n')
        *p-- = '\0';
}

// 解析参数
void str_split(const char *str, char *left, char *right, char c)
{
    char *p = strchr(str, c);
    if (p == NULL)
    {
        strcpy(left, str);
    }
    else
    {
        strncpy(left, str, p-str);
        strcpy(right, p+1);
    }
}

// 判断str是否全部是空白字符，是的话返回1，否则返回0
int str_all_space(const char *str)
{
    while (*str)
    {
        if (!isspace(*str)) 
            return 0;
        str++;
    }
    return 1;
}

// str转换为大写字符串
void str_upper(char *str)
{
    while(*str)
    {
        *str = toupper(*str); 
        str++;
    }
}
void str_trim_space(char *str)
{
    char *p = str;
    while(*str)
    {
        if (*str != ' ') 
            *p++ = *str;
        str++;
    }
    *p = '\0';
}

// 将str转换为long long类型
long long str_to_longlong(const char *str)
{
    /*atoll()*/
    long long result = 0;
    long long mult = 1;
    unsigned int len = strlen(str);

    if (len > 15)
        return 0;
/*
    for (unsigned int i = 0; i < len; i++)
    {
        char ch = str[len-i-1]; 
        long long val;
        if (ch > '9' || ch < '0')
            return 0;
        val = (ch - '0');
        val *= mult;
        result += val;
        mult *= 10;
    }
*/
    for (int i = len-1; i >= 0; i--)
    {
        char ch = str[i]; 
        long long val;
        if (ch > '9' || ch < '0')
            return 0;
        val = (ch - '0');
        val *= mult;
        result += val;
        mult *= 10;
    }

    return result;
}

// 将8进制转换为10进制
unsigned int str_octal_to_uint(const char *str)
{
    unsigned int result = 0;
    int seen_non_zero_digit = 0;

    while(1)
    {
        int digit = *str;
        if (!isdigit(digit) || digit > '7')
            break;

        if (digit != '0')
            seen_non_zero_digit = 1;

        if (seen_non_zero_digit)
        {
            result <<= 3; 
            result += (digit - '0');
        }
        str++;
    }
    return result;
}

