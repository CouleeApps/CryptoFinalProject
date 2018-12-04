#include <string.h>
#include <stdarg.h>

#include "handlers.h"

void User::part_channel(const std::string &ch_name) {
    auto &channel = channels[ch_name];
    auto itr = channel.find(this);
    if (itr != channel.end()) {
        channel.erase(itr);
    }
}

void user_handler(User *user, char **saveptr) {
    if (user->registered) {
        ssl_dprintf(&user->session, user->sd, "Invalid command\n");
        return;
    }
    
    char *tok = strtok_r(NULL, " ", saveptr);
    std::string name(tok ? tok : "");
    if (name.size() == 0) {
        ssl_dprintf(&user->session, user->sd, "You must provide a username\n");
        return;
    }

    user->name = name;
    user->registered = true;
    ssl_dprintf(&user->session, user->sd, "Welcome, %s\n", user->name.c_str());
}

void list_handler(User *user, char **saveptr) {
    char *tok = strtok_r(NULL, " ", saveptr);
    std::string name(tok ? tok : "");
    if (name[0] == '#') {
        name = name.substr(1);
    }
    
    {
        std::lock_guard<std::mutex> g(channels_mutex);
        auto itr = channels.find(name);
        if (itr == channels.end()) {
            ssl_dprintf(&user->session, user->sd, "There are currently %lu channels\n",
                    channels.size());
            for (auto channel : channels) {
                ssl_dprintf(&user->session, user->sd, "* %s\n", channel.first.c_str());
            }
        } else {
            ssl_dprintf(&user->session, user->sd, "There are currently %lu members\n#%s members:",
                    itr->second.size(), itr->first.c_str());
            for (auto chuser : itr->second) {
                ssl_dprintf(&user->session, user->sd, " %s", chuser->name.c_str());
            }
            ssl_dprintf(&user->session, user->sd, "\n");
        }
    }
}

void join_handler(User *user, char **saveptr) {
    char *tok = strtok_r(NULL, " ", saveptr);
    std::string name(tok ? tok : "");
    
    if (name.size() == 0) {
        ssl_dprintf(&user->session, user->sd, "Invalid JOIN command\n");
    } else {
        if (name[0] != '#') {
            ssl_dprintf(&user->session, user->sd, "Invalid channel name\n");
            return;
        }
        name = name.substr(1);
        {
            std::lock_guard<std::mutex> g(channels_mutex);
            if (channels[name].find(user) != channels[name].end()) {
                ssl_dprintf(&user->session, user->sd, "You are already in this channel\n");
                return;
            }
            for (auto user2 : channels[name]) {
                ssl_dprintf(&user2->session, user2->sd, "#%s> %s joined the channel\n",
                        name.c_str(), user->name.c_str());
            }
            channels[name].insert(user);
            ssl_dprintf(&user->session, user->sd, "Joined channel #%s\n", name.c_str());
        }
    }
}

void part_handler(User *user, char **saveptr) {
    char *tok = strtok_r(NULL, " ", saveptr);
    std::string name(tok ? tok : "");
    
    if (name.size() == 0) {
        std::lock_guard<std::mutex> g(channels_mutex);
        for (auto chit = channels.begin(); chit != channels.end();) {
            auto itr = chit->second.find(user);
            for (auto user2 : chit->second) {
                ssl_dprintf(&user2->session, user2->sd, "#%s> %s left the channel\n",
                        chit->first.c_str(), user->name.c_str());
            }
            if (itr != chit->second.end()) {
                user->part_channel(chit->first);
            }
            ++chit;
        }
    } else {
        if (name[0] == '#') {
            name = name.substr(1);
            std::lock_guard<std::mutex> g(channels_mutex);
            auto itr = channels.find(name);
            if (itr == channels.end()) {
                ssl_dprintf(&user->session, user->sd, "That channel does not exist\n");
            } else {
                auto itr2 = itr->second.find(user);
                if (itr2 != itr->second.end()) {
                    for (auto user2 : itr->second) {
                        ssl_dprintf(&user2->session, user2->sd, "#%s> %s left the channel\n",
                                itr->first.c_str(), user->name.c_str());
                    }
                    user->part_channel(itr->first);
                } else {
                    ssl_dprintf(&user->session, user->sd, "You are not a member of that channel\n");
                }
            }
        } else {
            ssl_dprintf(&user->session, user->sd, "Invalid channel name\n");
        }
    }
}

void operator_handler(User *user, char **saveptr) {
    if (!op_allowed) {
        ssl_dprintf(&user->session, user->sd, "Invalid OPERATOR command\n");
        return;
    }

    char *tok = strtok_r(NULL, " ", saveptr);
    std::string name(tok ? tok : "");
    if (name == pass) {
        user->op = true;
        ssl_dprintf(&user->session, user->sd, "OPERATOR status bestowed\n");
    } else {
        ssl_dprintf(&user->session, user->sd, "Invalid OPERATOR command\n");
    }
}

void kick_handler(User *user, char **saveptr) {
    if (!user->op) {
        ssl_dprintf(&user->session, user->sd, "You are not an OPERATOR\n");
        return;
    }

    //First word is the channel, rest until NL is the user
    char *tok = strtok_r(nullptr, " ", saveptr);
    std::string channel(tok ? tok : "");
    tok = strtok_r(nullptr, "\n", saveptr);
    std::string target(tok ? tok : "");

    User *tuser = find_user(target);
    if (tuser == nullptr) {
        ssl_dprintf(&user->session, user->sd, "User does not exist\n");
        return;
    }

    if (channel[0] != '#') {
        ssl_dprintf(&user->session, user->sd, "Channel does not exist\n");
        return;
    }
    channel = channel.substr(1);

    {
        std::lock_guard<std::mutex> g(channels_mutex);
        auto itr = channels.find(channel);
        if (itr == channels.end()) {
            ssl_dprintf(&user->session, user->sd, "Channel does not exist\n");
            return;
        }
        
        for (auto member : itr->second) {
            ssl_dprintf(&member->session, member->sd, "#%s> %s has been kicked from the channel\n",
                    channel.c_str(), user->name.c_str());
        }

        //Kick them out!
        user->part_channel(channel);
    }
}

void privmsg_handler(User *user, char **saveptr) {
    //First word is the target, rest until NL is the message
    char *tok = strtok_r(nullptr, " ", saveptr);
    std::string target(tok ? tok : "");
    //Technically there's no more newline in the message, so this just gets the rest
    tok = strtok_r(nullptr, "\n", saveptr);
    std::string message(tok ? tok : "");

    //Message can be at most 512 characters in length
    if (message.size() > 512) {
        return;
    }

    //Who are we sending to?
    bool target_is_channel = target[0] == '#';
    if (target_is_channel) {
        target = target.substr(1);
        std::lock_guard<std::mutex> g(channels_mutex);
        //Find channel
        auto found = channels.find(target);

        if (found != channels.end()) {
            auto channel = found->second;

            //Make sure you're in the channel before sending to it
            if (channel.find(user) == channel.end()) {
                ssl_dprintf(&user->session, user->sd, "You are not currently in #%s.\n",
                        found->first.c_str());
                return;
            }

            //Tell everybody
            for (auto chuser : channel) {
                // #Channel> Sender: Message
                ssl_dprintf(&chuser->session, chuser->sd, "#%s> %s: %s\n", found->first.c_str(),
                        user->name.c_str(), message.c_str());
            }
        }
    } else {
        //Send to single user
        User *utarget = find_user(target);

        if (utarget != nullptr) {
            // <<Sender Message
            ssl_dprintf(&utarget->session, utarget->sd, "<<%s %s\n", user->name.c_str(),
                    message.c_str());
            // Receiver>> Message
            ssl_dprintf(&user->session, user->sd, "%s>> %s\n", utarget->name.c_str(),
                    message.c_str());
        }
    }
}

void quit_handler(User *user, char **saveptr) {
    //Need to leave all the channels
    {
        std::lock_guard<std::mutex> g(channels_mutex);
        for (auto chit = channels.begin(); chit != channels.end(); ) {
            if (chit->second.find(user) != chit->second.end()) {
                for (auto user2 : chit->second) {
                    ssl_dprintf(&user2->session, user2->sd, "#%s> %s left the channel\n",
                            chit->first.c_str(), user->name.c_str());
                }
	            user->part_channel(chit->first);
            }
            ++chit;
        }
    }

    //Take us out of the user list
    {
        std::lock_guard<std::mutex> g(users_mutex);
        users.erase(std::find(users.begin(), users.end(), user));
    }

    user->registered = false;
}
