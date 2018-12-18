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

    for (let i = 0; i < chunked_data.length; i++) {
      if(constant.HEX.indexOf(chunked_data[i]) <= -1) {
        throw "Data must contain only hexdigits";
      }
    }

    return SecretSharer.share(chunked_data, this.total_number_of_node, this.min_consensus_node);
  }

  get_secrets_from_hex_string (chunked_data) {
    let data_len = chunked_data.length;
    if (data_len <= constant.MAX_HEX_LENGTH) {
      return this.get_secrets_from_valid_hex_string(chunked_data);
    }
    return `Hex string length must be less than ${constant.MAX_HEX_LENGTH}`;
  }

  get_chunk (idx, data_len) {
    let chunked_data = "";
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

  add_chunk (chunkSecrets) {
    for (let node = 0; node < this.total_number_of_node; node++) {
      this.secrets[node] = this.secrets[node] + chunkSecrets[node];
    }
  }

  chunked_text_to_chunked_secret (idx, data_len) {
    let temp_data = this.get_chunk(idx, data_len);
    let hex_temp_data = binascii.hexlify(temp_data);
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
    }
    return this.secrets;
  }

  add_index (secrets) {
    const filtered_secrets = secrets.map((s, index) => {
      return String(index + 1) + '-' + s;
      return s;
    });

    return filtered_secrets;
  }

  run () {
    // const result = this.add_index(this.get_secrets_from_plain_text());
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
    // console.log("FROM SPECIAL", secrets);
    let temp_data = this.recover_hex_string_secret(secrets)
    let recovered_data = binascii.unhexlify(temp_data);
    return String(recovered_data);
  }

  add_pieces_together (total_secrets) {
    this.data = [];
    for (let i=0;i<total_secrets;i++) {
      this.data.push([]);
    }

    for (let i = 0; i < this.secrets.length; i++) {
      let pieces = String(this.secrets[i]).split('^');
      for (let j=0; j < total_secrets; j++) {
        this.data[j].push(pieces[j]);
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
    for (let i = 0;i < total_secrets; i++) {
      recovered_data += this.decrypt_chunked_message(i);
    }
    return String(recovered_data);
  }

  recover_plain_text_secret () {
    let total_secrets = String(this.secrets[0]).split('^').length;

    if (total_secrets === 1) {
      return this.special_case(this.secrets);
    }

    this.add_pieces_together(total_secrets);
    console.log(this.data);
    return this.decrypt_whole_message(total_secrets);
  }

  run () {
    return this.recover_plain_text_secret();
  }
}

module.exports = {
  SecretGenerator,
  SecretRecoverer
}
