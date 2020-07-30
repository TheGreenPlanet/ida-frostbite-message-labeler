# dumped_file line format example: 
# [*] NetworkPerformanceProfileMessage: pMessage: 0x1bc3bc20 ( Category: -964876421 | Type: 880806691 ) T: 0x1444daf60 R: 0x140a9219f 
message_and_address_list = []

vftables_labeled = 0
vftables_failed = 0

messages_labeled = 0
messages_failed = 0

def final_results():
    global messages_labeled, messages_failed, vftables_labeled, vftables_failed
    print '======== Results ========'
    print 'Labeled functions: ' + str(messages_labeled) + ' Failed: ' + str(messages_failed)
    print 'Labeled vftables: ' + str(vftables_labeled) + ' Failed: ' + str(vftables_failed)


def label_msg_failed_detailed(message, location, msg):
    print '[!] ' + message + ' cursor: ' + str(hex(location)).rstrip('L') + ' ' + msg

def label_msg_failed(message, text):
    global messages_failed
    print '[!] ' + message + ' ' + text
    messages_failed += 1

def label_msg_success(msg):
    global messages_labeled
    print '[+] Labeled message: ' + msg
    messages_labeled += 1

def label_vftable_success(msg):
    global vftables_labeled
    print '[+] Labeled vftable: ' + msg
    vftables_labeled += 1

def label_vftable_failed(message, text):
    global vftables_failed
    print '[!] ' + text
    vftables_failed += 1


def get_real_address(curr_head):
    return idc.GetOperandValue(curr_head, 0)

def get_message_vftable(func_address):
    # 1. loop through the entire function
    function = idaapi.get_func(func_address)
    curr_head = function.startEA

    while curr_head < function.endEA:
        next_head = idaapi.next_head(curr_head, function.endEA)
        if idc.GetMnem(curr_head) == 'call' and idc.GetMnem(next_head) == 'lea':
            if idc.GetDisasm(curr_head).find('??0Message@fb@') != -1:
                return int(idc.GetOperandValue(next_head, 1))

        curr_head = next_head

    return -1

    # 2. find the ??0Message@fb@@IAE@HH@Z call

    # 3. get the first instance of the 'lea' instr

    # 4. this is our vftable

def get_message_func(message, address):
    message_vftable_memory_space = 20
    function = idaapi.get_func(address)
    max_address = address + message_vftable_memory_space
    function_start_address = function.startEA

    curr_head = max_address

    msg_ptr_loaded_stack_var = ''
    found_msg_ptr_loaded_stack_var = False

    real_address = -1

    while curr_head > function_start_address:
        prev_head = idaapi.prev_head(curr_head, function_start_address)
        
        if idc.GetMnem(curr_head) == 'call':
            # operand = idc.GetOpnd(curr_head, 0)
            current_func_disasm = idc.GetDisasm(curr_head)

            # find the func where the stack var is being loaded into
            if found_msg_ptr_loaded_stack_var:
                if idc.GetMnem(prev_head) == 'lea':
                    current_stack_var = idc.GetDisasm(prev_head)
                    if current_stack_var == msg_ptr_loaded_stack_var:
                        # exclude/parse out known non-message functions
                        if current_func_disasm.find('NetworkableMessage') == -1 and current_func_disasm.find('??0Message@fb@') == -1:                    
                            real_address = get_real_address(curr_head)
                            break

            # find the stack var
            if not found_msg_ptr_loaded_stack_var:
                if current_func_disasm.find('??1Message@fb@') != -1:
                    if idc.GetMnem(prev_head) == 'lea':
                        msg_ptr_loaded_stack_var = idc.GetDisasm(prev_head)
                        found_msg_ptr_loaded_stack_var = True
                    else:
                        label_msg_failed_detailed(message, curr_head, '??1Message@fb@ previous instr wasnt lea')
                        break

        curr_head = prev_head

    return int(real_address)


# 1. goto the next function being called
# 2. check the name of the destructor (there are 2 types, "fb::Message::~Message" or "fb::NetworkableMessage::~NetworkableMessage")
# 3. get the stack-var being loaded into the "rcx" register
# 4. go back up the registers and check every "call" made loading the stack var
# 5. check if the function calls "fb::Message::Message" or "fb::NetworkableMessage::NetworkableMessage", if so, return that address. Exception: if theres only a jmp inst, jump to that address
# additionally you could compare the type and category 

def label_dumped_messages(dump_file_path):
    global message_and_address_list
    
    # 1. read the message dump
    with open(dump_file_path, 'r') as f:
        # 2. create an list of the message name and its address
        for line in f:
            if '[*]' in line:
                message_end_index = line.find(': pMessage:')
                address_start_index = line.find('R: 0x') + 3
                if message_end_index != -1 and address_start_index != -1:
                    message = line[4:message_end_index]
                    address = line[address_start_index:len(line)-1]

                    # check for duplicates:
                    dupe = False
                    for p in message_and_address_list:
                        if p[0] == message:
                            dupe = True
                            break
                    # add to the list
                    if not dupe: 
                        message_and_address_list.append((message, int(address, 16)))
    
    # print(message_and_address_list)

    # 3. itterate through the list, in IDA, goto the address, find the message funciton, rename it
    for p in message_and_address_list:
        message_name = str(p[0])

        real_address = get_message_func(message_name, p[1])
        real_address_hex = hex(real_address)

        if real_address != -1:
            label_msg_success(message_name + ' at: ' + str(real_address_hex).rstrip('L'))
            # rename the real address
            idc.MakeName(real_address, '??0' + message_name + '@fb@@QAE@XZ')

            # get the vftable offset
            vftable_offset = get_message_vftable(real_address)
            vftable_offset_hex = hex(vftable_offset)

            if vftable_offset != -1:
                label_vftable_success(message_name + ' at: ' + str(vftable_offset_hex).rstrip('L'))
                # rename the vftable offset
                idc.MakeName(vftable_offset, '??_7' + message_name + '@fb@@6B@')
            else:
                label_vftable_failed(message_name, 'failed to find the vftable')
        else:
            label_msg_failed(message_name, 'failed to find the function address')
    
    final_results()
# if __name__ == '__main__':
#    label_dumped_messages("E:\\Games\\STAR WARS Battlefront II\\dispatchMessage_dump.txt")


# done!