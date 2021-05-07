import struct
import io


MAX_WINDOW_SIZE = 0x10000


get_bit = lambda data, bit_pos: \
    ((data[bit_pos >> 3] >> (7 - (bit_pos & 7))) & 1)


def upper_log2(n):
    if (n <= 0):
        return -1
    i = 0
    m = 1
    while (m < n):
        m <<= 1
        i += 1
    return i


def copy_bits_in_a_byte(dest_data, dest_bit_pos, src_data, src_bit_pos,
                        num_bits):
    dest_byte_pos = dest_bit_pos >> 3
    dest_bit_pos &= 7
    src_byte_pos = src_bit_pos >> 3
    src_bit_pos &= 7

    bits_to_copy = min(num_bits, 8 - dest_bit_pos)
    bit_mask = 0xFF >> dest_bit_pos
    bit_mask &= (0xFF << (8 - dest_bit_pos - bits_to_copy)) & 0xFF

    src_byte_bits = 8 - src_bit_pos

    if (bits_to_copy > src_byte_bits):
        src_word = (src_data[src_byte_pos] << 8) | src_data[src_byte_pos + 1]
        src_byte = (src_word >> (8 - (src_bit_pos - dest_bit_pos))) & 0xFF
    else:
        src_byte = src_data[src_byte_pos]
        if (src_bit_pos > dest_bit_pos):
            src_byte <<= src_bit_pos - dest_bit_pos
        elif (src_bit_pos < dest_bit_pos):
            src_byte >>= dest_bit_pos - src_bit_pos

    dest_data[dest_byte_pos] = ((dest_data[dest_byte_pos] &
                                 (bit_mask ^ 0xFF)) |
                                (src_byte & bit_mask))


def copy_bits(dest_data, dest_bit_pos, src_data, src_bit_pos, num_bits):
    bits_to_copy = min(num_bits, 8 - (dest_bit_pos & 7))
    copy_bits_in_a_byte(dest_data, dest_bit_pos, src_data, src_bit_pos,
                        bits_to_copy)
    num_bits -= bits_to_copy
    while (num_bits != 0):
        dest_bit_pos += bits_to_copy
        src_bit_pos += bits_to_copy
        bits_to_copy = min(num_bits, 8)
        copy_bits_in_a_byte(dest_data, dest_bit_pos, src_data, src_bit_pos,
                            bits_to_copy)
        num_bits -= bits_to_copy


def get_dword_val(data, bit_pos, num_bits):
    if (num_bits > 32):
        return -1

    s = bytearray(4 * b'\0')
    copy_bits(s, 32 - num_bits, data, bit_pos, num_bits)

    res = s[0]
    for i in range(3):
        res = (res << 8) | s[i + 1]
    return res


def decompress(data, unpack_len):
    if (unpack_len > 0x10000):
        return b''

    dec_data = b''

    bit_pos = 0

    wnd_pos = 0
    wnd_size = 0

    i = 0
    while (i < unpack_len):
        b = get_bit(data, bit_pos)
        bit_pos += 1
        if (b == 0):
            s = bytearray(b'\0')
            copy_bits(s, 0, data, bit_pos, 8)
            dec_data += s
            bit_pos += 8
            wnd_size += 1
            i += 1
        else:
            q = -1
            while (b != 0):
                q += 1
                b = get_bit(data, bit_pos)
                bit_pos += 1
            if (q > 0):
                ln = get_dword_val(data, bit_pos, q)
                if (ln < 0):
                    break
                ln += (1 << q) + 1
                bit_pos += q
            else:
                ln = 2

            num_bits = upper_log2(wnd_size)
            offset = get_dword_val(data, bit_pos, num_bits)
            if (offset < 0):
                break
            offset += wnd_pos
            bit_pos += num_bits

            for j in range(ln):
                dec_data += bytes([dec_data[offset + j]])

            wnd_size += ln;
            i += ln

        if (wnd_size > MAX_WINDOW_SIZE):
            wnd_pos += wnd_size - MAX_WINDOW_SIZE
            wnd_size = MAX_WINDOW_SIZE

    return dec_data


def decompress_data(data):
    dec_data = b''
    data_len = len(data)
    i = 0

    while (i < data_len):
        unpack_len, pack_len = struct.unpack_from('<HH', data, i)
        i += 4

        eff_unpack_len = unpack_len if (unpack_len != 0) else 0x10000

        if (unpack_len != pack_len):
            # Compressed chunk
            if (pack_len != 0):
                dec_data += decompress(data[i : i + pack_len],
                                       eff_unpack_len)
                i += pack_len
        else:
            # Uncompressed chunk
            dec_data += data[i : i + eff_unpack_len]
            i += eff_unpack_len

    return dec_data


def decompress_file(in_filename, out_filename):
    with io.open(in_filename, 'rb') as fin:

        with io.open(out_filename, 'wb') as fout:

            while True:
                data = fin.read(4)
                if (len(data) == 0):
                    break
                if (len(data) != 4):
                    return False

                unpack_len, pack_len = struct.unpack('<HH', data)

                eff_unpack_len = unpack_len if (unpack_len != 0) else 0x10000

                if (unpack_len != pack_len):
                    # Compressed chunk
                    if (pack_len != 0):
                        data = fin.read(pack_len)
                        if (len(data) != pack_len):
                            return False
                        dec_data = decompress(data, eff_unpack_len)
                        fout.write(dec_data)
                        if (len(dec_data) != eff_unpack_len):
                            return False
                else:
                    # Uncompressed chunk
                    data = fin.read(eff_unpack_len)
                    fout.write(data)
                    if (len(data) != eff_unpack_len):
                        return False

    return True


if __name__ == '__main__':
    import sys

    if len(sys.argv) != 2:
        print('Usage: '+ sys.argv[0] + ' filename')
        sys.exit(0)

    in_filename = sys.argv[1]
    out_filename = in_filename + '.dec'
    res = decompress_file(in_filename, out_filename)
    if res:
        print('Done!')
    else:
        print('Error!')
