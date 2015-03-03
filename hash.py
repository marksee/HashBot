'''
hash.py - Willie module that calls hashcat
Love, DanMcInerney
'''
# Willie installation
# https://flexion.org/posts/2014-08-installing-willie-irc-bot-on-debian.html

import os
import re
import time
import pipes
import string
import random
import paramiko
import subprocess
import multiprocessing
from willie.module import commands, example

sessions = []
all_rules = ['best64.rule',
            'combinator.rule',
            'd3ad0ne.rule',
            'generated.rule',
            'generated2.rule',
            'hybrid',
            'Incisive-leetspeak.rule',
            'InsidePro-HashManager.rule',
            'InsidePro-PasswordsPro.rule',
            'leetspeak.rule',
            'Ninja-leetspeak.rule',
            'oscommerce.rule',
            'passwordspro.rule',
            'rockyou-30000.rule',
            'specific.rule',
            'T0XlC-insert_00-99_1950-2050_toprules_0_F.rule',
            'T0XlC-insert_space_and_special_0_F.rule',
            'T0XlC-insert_top_100_passwords_1_G.rule',
            'T0XlC.rule',
            'T0XlCv1.rule',
            'toggles1.rule',
            'toggles2.rule',
            'toggles3.rule',
            'toggles4.rule',
            'toggles5.rule']


@commands('help')
def help(bot, trigger):
    '''
    Print out the rules and hash types
    '''
    # Examples
    bot.say('Usage: ".hash [hashmode] [ruleset] [hash] [hash] [hash] ..."')
    bot.say('Type ".rules" to see a list of rules available')
    bot.say('Type ".sessions" to see a list of active sessions')
    bot.say('Type ".kill <sessionname>" to kill an active session (Enter one session at a time)')

@commands('rules')
def rules(bot, trigger):
    '''
    Hardcoded list of rules, might make the bot SSH to the rules
    dir and list them that way at some point but for now this is
    easier and the rules don't change hardly ever
    '''
    bot.say('Rules:')
    bot.say('%s' % ' | '.join(all_rules))

@commands('kill')
def kill(bot, trigger):
    '''
    Kill a session
    Cleanup occurs automatically
    '''
    global sessions
    kill_session = trigger.group(2)
    if kill_session:
        kill_session = kill_session.strip()
        bot.say('Killing session: %s' % kill_session)
        # pipes.quote will quote out the input to prevent shell injection
        cmd = 'ps faux | grep -v grep | grep " %s -m " | awk \'{print $2}\' | xargs kill' % pipes.quote(kill_session)
        os.system(cmd)
    else:
        bot.say('No session by that name found. Please enter a single session to kill, .kill <sessionname>, \
or type .sessions to see all sessions')

@commands('sessions')
def sessions_printer(bot, trigger):
    '''
    Print all sessions
    '''
    if len(sessions) == 0:
        bot.say('No current sessions initiatied by HashBot')
    else:
        bot.say('Current sessions: %s' % ' '.join(sessions))

@commands('hash')
def hash(bot, trigger):
    '''
    Function that's called when user types .hash
    '''
    sanitize = re.compile('[\W_]+')
    # trigger = u'.hash arg1 arg2...'
    # trigger.group(1) = u'hash'
    # trigger.group(2) = u'arg1 arg2...'
    if not trigger.group(2):
        wrong_cmd(bot)
        return
    args = trigger.group(2).split()
    if len(args) > 1:

        # Sanitize the nick
        nick = str(trigger.nick)
        sani_nick = sanitize.sub('', nick)

        mode, rule, hashes = get_options(bot, args, nick)
        if mode and rule and hashes:
            # Handle hashcat sessions
            sessionname = session_handling(sani_nick)
            run_cmds(bot, nick, sani_nick, sessionname, mode, rule, hashes)
    else:
        wrong_cmd(bot)

def session_handling(sani_nick):
    '''
    Keep track of the sessions
    '''
    global sessions

    # Prevent dupe sessions
    counter = 1
    sessionname = sani_nick
    while sessionname in sessions:
        sessionname = sani_nick + str(counter)
        counter += 1

    # Limit total number of sessions
    if len(sessions) > 100:
        sessions = sessions[75:]
    sessions.append(sessionname)

    return sessionname

def get_options(bot, args, nick):
    '''
    Grab the args the user gives
    '''
    common_hashcat_codes = {'ntlm':'1000', 'netntlmv2':'5600', 'netntlmv1':'5500',
                            'sha1':'100', 'md5':'0', 'sha512':'1800', 'kerberos':'7500'}
    hashes = args[2:]
    if len(hashes) == 0:
        bot.say('No hashes entered. Please enter in form: .hash [hashtype] [ruleset] [hash] [hash] ...')
        return None, None, None
    mode = args[0]
    if mode in common_hashcat_codes:
        mode = common_hashcat_codes[mode]
    rule = args[1]
    if rule not in all_rules:
        bot.msg(nick,'Defaulting to passwordspro.rule as the entered ruleset does not exist. Type .rules \
to see a list of available rulesets.')
        rule = 'passwordspro.rule'

    return mode, rule, hashes

def run_cmds(bot, nick, sani_nick, sessionname, mode, rule, hashes):
    '''
    Handle interaction with crackerbox
    '''

    write_hashes_to_file(bot, hashes, nick, sessionname)

    cmd = '/coalfire/cracking/hashcat/oclHashcat-1.31/cudaHashcat-1.31/cudaHashcat64.bin \
--session %s -m %s -o /home/hashbot/%s-output.txt /tmp/%s-hashes.txt /coalfire/cracking/wordlists/* \
-r /coalfire/cracking/hashcat/oclHashcat-1.31/cudaHashcat-1.31/rules/%s'\
% (sessionname, mode, sessionname, sessionname, rule)

    split_cmd = cmd.split()
    bot.say('Hashcat session name: %s' % sessionname)
    bot.msg(nick, 'Cmd: %s' % cmd)
    hashcat_cmd = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
    #out, err = hashcat_cmd.communicate()
    # Continuously poll cracked pw file while waiting for hashcat to finish
    cracked = find_cracked_pw(bot, nick, sessionname, hashcat_cmd)
    summary, err = hashcat_cmd.communicate()
    # Check for errors
    if 'WARNING: Hashfile' in summary:
        bot.say('There was a problem with at least one of your hashes. \
                Are you sure you entered them/it correctly? \
                Check the summary file for more information.')

    cleanup(bot, nick, sessionname, cracked, summary)

def write_hashes_to_file(bot, hashes, nick, sessionname):
    '''
    Write to /tmp/sessionname-hashes.txt
    '''
    filename = '/tmp/%s-hashes.txt' % sessionname
    with open(filename, 'a+') as f:
        for h in hashes:
            h = clean_hash(bot, h, nick)
            if h != None:
                f.write(h+'\n')

def clean_hash(bot, h, nick):
    '''
    Sanitize and confirm hash doesn't have blank hex/unicode chars
    '''
    # Sometimes copy pasta causes blank characters at the end or beginning
    try:
        h.decode('utf8')
    except UnicodeEncodeError:
        bot.msg(nick, 'Unicode encode error with hash: %s' % repr(h))
        bot.msg(nick, 'If you copy and pasted it, try just deleting and retyping \
the first and last characters')
        return

    return h

def find_cracked_pw(bot, nick, sessionname, hashcat_cmd):
    '''
    While the hashcat cmd is running, constantly check sessionname-output.txt
    for cracked hashes
    '''
    cracked = []
    # When exit_status_ready() is True, cmd has completed
    while hashcat_cmd.poll() == None:
        time.sleep(1)
	cracked_pws = '/home/hashbot/%s-output.txt' % sessionname
	if os.path.isfile(cracked_pws):
            with open(cracked_pws) as f:
                for l in f.readlines():
                    if l not in cracked:
                        bot.msg(nick, 'Cracked! %s' % l)
                        cracked.append(l)
    return len(cracked)

def cleanup(bot, nick, sessionname, cracked, summary):
    '''
    Cleanup the left over files, save the hashes
    '''
    global sessions

    identifier = ''
    for x in xrange(0,6):
        identifier += random.choice(string.letters)

    cracked_file = '/home/hashbot/%s-%s-cracked.txt' % (sessionname, identifier)
    summary_file = '/home/hashbot/%s-%s-summary.txt' % (sessionname, identifier)

    subprocess.call(['rm', '/tmp/%s-hashes.txt' % sessionname]) 
    subprocess.call(['rm', '-rf', '/home/hashbot/%s.pot' % sessionname, 
                     '/home/hashbot/%s.log' % sessionname,
                     '/home/hashbot/%s.induct' % sessionname, 
                     '/home/hashbot/%s.restore' % sessionname, 
                     '/home/hashbot/%s.outfiles' % sessionname]) 
    cracked_pws = '/home/hashbot/%s-output.txt' % sessionname
    if os.path.isfile(cracked_pws):
        subprocess.call(['mv', '/home/hashbot/%s-output.txt' % sessionname, cracked_file])
    with open(summary_file, 'w+') as f:
        f.write(summary)
    sessions = [x for x in sessions if x != sessionname]
    bot.reply('completed session %s and cracked %s hash(es)' % (sessionname, str(cracked)))
    bot.msg(nick,'Hashcat finised, %d hash(es) stored on 10.0.0.240 at \
/home/hashbot/%s-%s-cracked.txt and %s-%s-summary.txt'\
% (cracked, sessionname, identifier, sessionname, identifier))

def wrong_cmd(bot):
    bot.say('Please enter hashes in the following form:')
    bot.say('.hash [hashtype] [ruleset] [hash] [hash] [hash] ...')
    bot.say('.hash ntlmv2 best64.rule 9D7E463A630AD...')
    bot.say('Use ".help" to see available rulesets and hashtypes')
