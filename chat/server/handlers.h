#ifndef __HANDLERS_H_
#define __HANDLERS_H_

#include <list>
#include <unordered_map>
#include <vector>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <thread>
#include <mutex>
#include <set>
#include <map>
#include <algorithm>

#include "../../ssl/ssl.h"

struct User {
    std::string name;
    int sd;
    ssl_session session;
    bool op;
    bool registered;

    User(int sd_, ssl_session session_) : sd(sd_), session(session_), op(false), registered(false) {}

    // Return true if we were the last person in the channel
    void part_channel(const std::string &ch_name);
};

typedef std::set<User *> Channel;

extern std::string pass;
extern bool op_allowed;
extern std::list<User *> users;
extern std::mutex users_mutex;
extern std::map<std::string, Channel> channels;
extern std::mutex channels_mutex;

inline User *find_user(const std::string &name) {
    std::lock_guard<std::mutex> g(users_mutex);
    auto found = std::find_if(users.begin(), users.end(), [name](User *user)->bool{
        return user->name == name;
    });
    if (found == users.end()) {
        return nullptr;
    }
    return *found;
}

template<typename ...Args>
void ssl_dprintf(ssl_session *session, int sd, const char *format, Args &&...args) {
    char buffer[1024];
    ssize_t length = snprintf(buffer, 1024, format, args...);
    ssl_send(sd, buffer, length, session);
}

void user_handler    (User *user, char **saveptr);
void list_handler    (User *user, char **saveptr);
void join_handler    (User *user, char **saveptr);
void part_handler    (User *user, char **saveptr);
void operator_handler(User *user, char **saveptr);
void kick_handler    (User *user, char **saveptr);
void privmsg_handler (User *user, char **saveptr);
void quit_handler    (User *user, char **saveptr);

#endif
