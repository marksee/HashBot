'''
hash.py - Willie module that calls hashcat
Love, DanMcInerney
'''
# Willie installation
# https://flexion.org/posts/2014-08-installing-willie-irc-bot-on-debian.html

import os
import re
import time
import glob
import pipes
import string
import random
import signal
import paramiko
import subprocess
import multiprocessing
from willie.module import commands, example

sessions = {} 
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
    bot.msg(trigger.nick, 'Usage: ".hash [hashmode] [ruleset] [hash] [hash] [hash] ..."')
    bot.msg(trigger.nick, 'Type ".rules" to see a list of rules available')
    bot.msg(trigger.nick, 'Type ".sessions" to see a list of active sessions')
    bot.msg(trigger.nick, 'Type ".kill <sessionname>" to kill an active session; enter one session at a time')
    bot.msg(trigger.nick, 'Output files are dumped to 10.0.0.240:/home/trcadmin/hcoutput/HashBot in format <sessionname>-cracked-<6 char ID>.txt')

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
        if kill_session in sessions:
            bot.say('Killing session: %s' % kill_session)
            os.killpg(sessions[kill_session].pid, signal.SIGTERM)
            return

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
        sessions_list = [k for k in sessions]
        bot.say('Current sessions: %s' % ' '.join(sessions_list))

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
    # Prevent dupe sessions
    counter = 1
    sessionname = sani_nick
    while sessionname in sessions:
        sessionname = sani_nick + str(counter)
        counter += 1

    return sessionname

def get_options(bot, args, nick):
    '''
    Grab the args the user gives
    '''
    common_hashcat_codes = {'ntlm':'1000', 'netntlmv2':'5600', 'ntlmv2':'5600', 'netntlmv1':'5500',
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
    global sessions

    write_hashes_to_file(bot, hashes, nick, sessionname)

    wordlists = ' '.join(glob.glob('/home/trcadmin/wordlists/crackstation.txt'))
    cmd = '/home/trcadmin/oclHashcat-1.35/oclHashcat64.bin \
--session %s -m %s -o /home/trcadmin/hcoutput/HashBot/%s-output.txt /tmp/%s-hashes.txt %s \
-r /home/trcadmin/oclHashcat-1.35/rules/%s'\
% (sessionname, mode, sessionname, sessionname, wordlists, rule)
    print_cmd = '/home/trcadmin/oclHashcat-1.35/oclHashcat64.bin \
--session %s -m %s -o /home/trcadmin/hcoutput/HashBot/%s-output.txt /tmp/%s-hashes.txt /home/trcadmin/wordlists/crackstation.txt \
-r /home/trcadmin/oclHashcat-1.35/rules/%s'\
% (sessionname, mode, sessionname, sessionname, rule)

    split_cmd = cmd.split()
    bot.say('Hashcat session name: %s' % sessionname)
    bot.msg(nick, 'Cmd: %s' % print_cmd)

    # Run hashcat
    hashcat_cmd = subprocess.Popen(split_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, preexec_fn=os.setsid)#, close_fds=True)#, shell=True)
    sessions[sessionname] = hashcat_cmd

    # Continuously poll cracked pw file while waiting for hashcat to finish
    num_cracked, output = find_cracked_pw(bot, nick, sessionname, hashcat_cmd)

    # Check for errors
    # If there's too many warning hashbot will hang trying to print the warnings
    # so only print the first warning/error
    #if 'WARNING:' in output:
    #    warning = 'WARNING:{0}'.format(output.split('WARNING:')[1])
    #    bot.say(warning.strip())
    if 'ERROR:' in output:
        error = 'ERROR:{0}'.format(output.split('ERROR:')[1])
        bot.say(error.strip())

    cleanup(bot, nick, sessionname, num_cracked, output)

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
    cracked_pws = '/home/trcadmin/hcoutput/HashBot/%s-output.txt' % sessionname
    output = ''

    # When exit_status_ready() is True, cmd has completed
    while hashcat_cmd.poll() == None:
        time.sleep(.5)
	
        # Prevent the buffer from filling and causing a hang
        # Too much info to a PIPE without reading from it
        # will result in a hang
        for line in iter(hashcat_cmd.stdout.readline, b''):
            output += line

        if os.path.isfile(cracked_pws):
            with open(cracked_pws) as f:
                for l in f.readlines():
                    if l not in cracked:
                        bot.msg(nick, 'Cracked! %s' % l)
                        cracked.append(l)

    return len(cracked), output

def cleanup(bot, nick, sessionname, cracked, output):
    '''
    Cleanup the left over files, save the hashes
    '''
    global sessions

    identifier = ''
    for x in xrange(0,6):
        identifier += random.choice(string.letters)
	 
	#log_file = '/home/trcadmin/hcoutput/HashBot/%s-log-%s.txt' % (sessionname, identifier)
	#log = '/home/trcadmin/hcoutput/HashBot/%s.log' % sessionname
	#err_file = '/home/trcadmin/hcoutput/HashBot/%s-errors-%s.txt' % (sessionname, identifier)
	output_file = '/home/trcadmin/hcoutput/HashBot/%s-output-%s.txt' % (sessionname, identifier)
	cracked_file = '/home/trcadmin/hcoutput/HashBot/%s-cracked-%s.txt' % (sessionname, identifier)
	cracked_pws = '/home/trcadmin/hcoutput/HashBot/%s-output.txt' % sessionname

    if len(output) > 0:
        with open(output_file, 'a+') as f:
            f.write(output)

    # Move the cracked hashes and log files to ID'd filenames
    if os.path.isfile(cracked_pws):
        subprocess.call(['mv', '/home/trcadmin/hcoutput/HashBot/%s-output.txt' % sessionname, cracked_file])
    #subprocess.call(['mv', '/home/trcadmin/hcoutput/HashBot/%s.log' % sessionname, log_file])
   
    # Cleanup files
    subprocess.call(['rm', '-rf', '/home/trcadmin/hcoutput/HashBot/%s.pot' % sessionname, 
                     '/tmp/%s-hashes.txt' % sessionname, 
                     '/home/trcadmin/hcoutput/HashBot/%s.induct' % sessionname, 
                     '/home/trcadmin/hcoutput/HashBot/%s.restore' % sessionname, 
                     '/home/trcadmin/hcoutput/HashBot/%s.outfiles' % sessionname]) 

    del sessions[sessionname]
    bot.reply('completed session %s and cracked %s hash(es)' % (sessionname, str(cracked)))
    bot.msg(nick,'Hashcat finised, %d hash(es) stored on 10.110.1.19 at \
/home/trcadmin/hcoutput/HashBot/%s-cracked-%s.txt'\
% (cracked, sessionname, identifier))

def wrong_cmd(bot):
    bot.say('Please enter hashes in the following form:')
    bot.say('.hash [hashtype] [ruleset] [hash] [hash] [hash] ...')
    bot.say('.hash ntlmv2 best64.rule 9D7E463A630AD...')
    bot.say('Use ".help" to see available rulesets and hashtypes')
