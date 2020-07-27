# dumped_file line format example: 
# [*] NetworkPerformanceProfileMessage: pMessage: 0x1bc3bc20 ( Category: -964876421 | Type: 880806691 ) T: 0x1444daf60 R: 0x140a9219f 
def msg_failed(location, msg):
    print '[!] ' + str(hex(location)) + ' ' + msg

def get_address_from_disasm():

def find_message_func(message, address):
    message_destructor_memory_space = 20
    function = idaapi.get_func(address)
    max_address = address + message_destructor_memory_space
    function_start_address = function.startEA

    current_location = max_address

    msg_loaded_stack_var = ''
    msg_loaded_stack_var_found = False

    found_real_address = False

    while current_location > function_start_address and not found_real_address:
        # just enter all calls and do step 5
        
        if idc.GetMnem(current_location) == 'call':
            func_disasm = idc.GetDisasm(current_location)
            func_address = ''

            # find the stack var
            if not msg_loaded_stack_var_found:
                if func_disasm.find('Message') != -1:
                    if idc.GetMnem(idc.prev_head(current_location)) == 'rcx':
                        msg_loaded_stack_var = idc.GetDisasm(idc.prev_head(current_location))
                        msg_loaded_stack_var_found = True
                    else
                        msg_failed(current_location, 'Message previous instr wasnt rcx')
            # find the func where the stack var is being loaded into
            if idc.GetMnem(idc.prev_head(current_location)) == 'rcx':
                rcx = idc.GetDisasm(idc.prev_head(current_location))
                if rcx == msg_loaded_stack_var:                    
                    if func_disasm.find('sub_') != -1:
                        
                        found_real_address = True
                    else
                        msg_failed(current_location, 'The suspected functions name is already labeled, ' + func_name)



        current_location = idc.prev_head(current_location)


# 1. goto the next function being called
# 2. check the name of the destructor (there are 2 types, "fb::Message::~Message" or "fb::NetworkableMessage::~NetworkableMessage")
# 3. get the stack-var being loaded into the "rcx" register
# 4. go back up the registers and check every "call" made loading the stack var
# 5. check if the function calls "fb::Message::Message" or "fb::NetworkableMessage::NetworkableMessage", if so, return that address. Exception: if theres only a jmp inst, jump to that address
# additionally you could compare the type and category 

def label_dumped_messages(dump_file_path):
    message_and_address_list = []
    
    # 1. read the message dump
    with open(dump_file_path, 'r') as f:
        # 2. create an list of the message name and its address
        for line in f:
            if '[*]' in line:
                message_end_index = line.find(': pMessage:')
                address_start_index = line.find('R: 0x') + 3
                if message_end_index != -1 and address_start_index != -1:
                    message = line[4:message_end_index]
                    address = line[address_start_index:len(line)-2]

                    # check for duplicates:
                    dupe = False
                    for p in message_and_address_list:
                        if p[0] == message:
                            dupe = True
                            break
                    # add to the list
                    if not dupe: 
                        message_and_address_list.append((message, hex(int(address, 16))))
    
    print(message_and_address_list)

    # 3. itterate through the list, in IDA, goto the address, find the message funciton, rename it
    for p in message_and_address_list:
        real_address = find_message_func(p[0], p[1])
        if real_address:
            # rename the real address
            idc.MakeName(real_address, p[0])

if __name__ == '__main__':
    label_dumped_messages("E:\\Games\\STAR WARS Battlefront II\\dispatchMessage_dump.txt")


# done!