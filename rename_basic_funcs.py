import idaapi
import ida_bytes
import idautils

def main():
    patterns = {
        'set_eax_to_one': b'\xB0\x01\xC3',
        'set_eax_to_zero': b'\x33\xC0\xC3',
        'copy_ecx_into_eax': b'\x8B\xC1\xC3',
        'set_eax_to_zero2': b'\x33\xC0\xC2\x04\x00',
        'set_al_to_zero': b'\x30\xC0\xC3',
        'xor_eax' : b'\x33\xC0',
        'get_first_occurence_of_the_substring_in_string': b'\x55\x8B\xEC\x8B\x45\x0C\x50\x8B\x4D\x08\x51\xFF\x15\xA0\xA1\x40\x00\x83\xC4\x08\x5D\xC3',
        'alloc_mem_and_return_poiner': b'\x55\x8B\xEC\x8B\x45\x08\x50\xFF\x15\x94\xA1\x40\x00\x83\xC4\x04\x5D\xC3',
        'free_mem_block': b'\x55\x8B\xEC\x8B\x45\x08\x50\xFF\x15\x90\xA1\x40\x00\x83\xC4\x04\x5D\xC3',
        'get_string_lenth': b'\x55\x8B\xEC\x8B\x45\x08\x50\xFF\x15\xDC\xA0\x40\x00\x5D\xC3',
        'Delete_critical_section': b'\x55\x8B\xEC\x51\x89\x4D\xFC\x8B\x45\xFC\x50\xFF\x15\xC0\xA0\x40\x00\x33\xC0\x8B\xE5\x5D\xC3',
        'Interlocked_Increment': b'\x55\x8B\xEC\x8B\x45\x08\x50\xFF\x15\x00\xA1\x40\x00\x5D\xC2\x04\x00',
        'Interlocked_Decrement': b'\x55\x8B\xEC\x8B\x45\x08\x50\xFF\x15\xFC\xA0\x40\x00\x5D\xC2\x04\x00',
        'compare_mem': b'\x55\x8B\xEC\x6A\x10\x8B\x45\x0C\x50\x8B\x4D\x08\x51\xE8\xDC\x63\x00\x00\x83\xC4\x0C\xF7\xD8\x1B\xC0\x83\xC0\x01\x5D\xC3',
    }
    renamed=0
    for name, pattern in patterns.items():
        print('Iterating ' + name)
        ea=ida_ida.inf_get_min_ea()
        counter=0 
        while ea < ida_ida.inf_get_max_ea():
            ea = ida_bytes.bin_search(ea, ida_ida.inf_get_max_ea(),pattern,None,1,ida_bytes.BIN_SEARCH_FORWARD|ida_bytes.BIN_SEARCH_NOBREAK|ida_bytes.BIN_SEARCH_NOSHOW)
            if ea == ida_idaapi.BADADDR:
                # not found
                print('Ending: ' + name)
                break
            else:
                print(ea)
                new_name="{}_{}".format(name, counter)
                idc.set_name(ea,new_name)
                counter+=1
                renamed+=1
                ea += 1
    print("{} renamed".format(renamed))
if __name__== '__main__':
    main()
   