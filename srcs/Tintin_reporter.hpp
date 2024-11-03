#ifndef TINTIN_REPORTER_HPP
#define TINTIN_REPORTER_HPP

enum log_type
{
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR,
    LOG_USER
};

class Tintin_reporter
{
private:
    const char* _data;
    Tintin_reporter();
    ~Tintin_reporter();
    Tintin_reporter( const Tintin_reporter &tintin_reporter );
    Tintin_reporter	&operator=( const Tintin_reporter& tintin_reporter );

public:
    
    static int log_message(const char* message, log_type type);    
};



#endif