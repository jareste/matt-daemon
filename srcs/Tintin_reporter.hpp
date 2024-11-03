#ifndef TINTIN_REPORTER_HPP
#define TINTIN_REPORTER_HPP

class Tintin_reporter
{
private:
    const char* _data;

public:
    Tintin_reporter();
    ~Tintin_reporter();
    Tintin_reporter( const Tintin_reporter &tintin_reporter );
    Tintin_reporter	&operator=( const Tintin_reporter& tintin_reporter );

    int log_message(const char* message);    
};



#endif