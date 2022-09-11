import idaapi
import ida_bytes
import idautils

def main():
    patterns = {
        'call eax': b'\xFF\xD0',
        'call ebx': b'\xFF\xD3',
        'call ecx': b'\xFF\xD1',
        'call edx': b'\xFF\xD2',
        'call esi': b'\xFF\xD6',
        'call edi': b'\xFF\xD7',
        'call esp': b'\xFF\xD4',
        'call ebp': b'\xFF\xD5',
        'call r8': b'\x41\xFF\xD0',
        'call r9': b'\x41\xFF\xD1',
        'call r10': b'\x41\xFF\xD2',
        'call r12': b'\x41\xFF\xD4',
        'jump eax': b'\xFF\xE0',
        'jump edx': b'\xFF\xE2',
        'jump edi': b'\xFF\xE7',
        'jump ebx': b'\xFF\xE3',
        'jump ecx': b'\xFF\xE1',
        'jump esi': b'\xFF\xE6',
        'jump esp': b'\xFF\xE4',
        'jump ebp': b'\xFF\xE5'
    }
    counter=0
    for name, pattern in patterns.items():
        print('Iterating ' + name)
        ea=ida_ida.inf_get_min_ea()
        while ea < ida_ida.inf_get_max_ea():
            ea = ida_bytes.bin_search(ea, ida_ida.inf_get_max_ea(),pattern,None,1,ida_bytes.BIN_SEARCH_FORWARD|ida_bytes.BIN_SEARCH_NOBREAK|ida_bytes.BIN_SEARCH_NOSHOW)
            if ea == ida_idaapi.BADADDR:
                # not found
                print('Ending: ' + name)
                break
            else:
                print(ea)
                idc.add_bpt(ea)
                ea += 1
                counter+=1
    print("{} br set".format(counter))
if __name__== '__main__':
    main()