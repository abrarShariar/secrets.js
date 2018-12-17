const SecretSharer = require('../secrets.js');
const constant = require('./constant');
const binascii = require('binascii');

const is_valid = (data) => {
  for (let char of data) {
    let value = Number(char);
    if (value < 32 || value > 126) {
      return false;
    }
    return true;
  }
}

class SecretGenerator {
  constructor (data, min_consensus_node = 3, total_number_of_node = 5) {
    this.data = data
    this.min_consensus_node = min_consensus_node
    this.total_number_of_node = total_number_of_node
    this.secrets = new Array(total_number_of_node).fill("", 0);
  }

  is_valid_length (chunked_data) {
    if (chunked_data.length > constant.MAX_HEX_LENGTH) {
      return false;
    }
    return true;
  }

  get_secrets_from_valid_hex_string (chunked_data) {
    if (this.is_valid_length(chunked_data) === false) {
      throw `Data length must be less than ${constant.MAX_HEX_LENGTH} character`;
    }

    chunked_data.forEach((x) => {
      if(constant.HEX.indexOf(x) <= -1) {
        throw "Data must contain only hexdigits";
      }
    });

    return SecretSharer.share(chunked_data, this.min_consensus_node, this.total_number_of_node);
  }

  get_secrets_from_hex_string (chunked_data) {
    let data_len = chunked_data.length;
    if (data_len <= constant.MAX_HEX_LENGTH) {
      return this.get_secrets_from_valid_hex_string(chunked_data);
    }
    return `Hex string length must be less than ${constant.MAX_HEX_LENGTH}`;
  }

  get_chunk (idx, data_len) {
    chunked_data = "";
    for(let i=idx; i < Math.min(data_len, idx+constant.MAX_CHUNK_LENGTH); i++) {
      chunked_data += this.data[i];
    }
    return chunked_data;
  }

  add_caps () {
    for (let node = 0; node < this.total_number_of_node; node++) {
      this.secrets[node] = this.secrets[node] + "^";
    }
  }

  add_chunk () {
    for (let node = 0; node < this.total_number_of_node; node++) {
      this.secrets[node] = this.secrets[node] + chunkSecrets[node];
    }
  }

  chunked_text_to_chunked_secret (idx, data_len) {
    let temp_data = this.get_chunk(idx, data_len);
    hex_temp_data = binascii.hexlify(temp_data);
    return this.get_secrets_from_hex_string(hex_temp_data);
  }

  get_secrets_from_plain_text () {
    if (is_valid(this.data) === false)  {
      throw "Data must contain only ascii character";
    }

    let data_len = this.data.length;
    for (let idx=0; idx < data_len; idx += constant.MAX_CHUNK_LENGTH) {
      let chunkSecrets = this.chunked_text_to_chunked_secret(idx, data_len);
      if (idx > 0) {
          this.add_caps();
      }
      this.add_chunk(chunkSecrets);
      return this.secrets;
    }
  }

  run () {
    return this.get_secrets_from_plain_text();
  }
}

class SecretRecoverer {

  constructor (secrets) {
    this.secrets = secrets;
    this.data = null;
  }

  recover_hex_string_secret (hex_string) {
    return SecretSharer.combine(hex_string);
  }

  special_case (secrets) {
    let temp_data = this.recover_hex_string_secret(secrets)
    let recovered_data = binascii.unhexlify(temp_data);
    return String(recovered_data);
  }

  add_pieces_together (total_secrets) {
    this.data = new Array(total_secrets).fill([], 0);
    for (let i = 0; i < this.secrets.length; i++) {
      let pieces = str(this.secrets[i]).split('^');
      for (let j=0; j < total_secrets.length; j++) {
        this.data[j].append(pieces[j]);
      }
    }
  }

  decrypt_chunked_message (idx) {
    let hex_sub_key = this.recover_hex_string_secret(this.data[idx]);
    let sub_key = binascii.unhexlify(hex_sub_key);
    return sub_key;
  }

  decrypt_whole_message (total_secrets) {
    let recovered_data = "";
    for (let i = 0;i < total_secrets.length; i++) {
      recovered_data += this.decrypt_chunked_message(i);
    }
    return String(recovered_data);
  }

  recover_plain_text_secret () {
    // NEED TO FIX THIS
    let total_secrets = (String(this.secrets[0]).match(/^/g) || []).length + 1;
    if (total_secrets === 1) {
      return this.special_case(this.secrets);
    }

    this.add_pieces_together(total_secrets);
    return this.decrypt_whole_message(total_secrets);
  }

  run () {
    return this.recover_plain_text_secret();
  }
}
