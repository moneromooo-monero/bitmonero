#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <vector>
#include <deque>
#include <map>
#include <unordered_map>

struct Transaction
{
  uint64_t height;
  std::vector<uint64_t> inputs;
  std::vector<uint64_t> outputs;
};

struct Chain
{
  std::vector<Transaction> txs;
  std::unordered_multimap<uint64_t, size_t> inputs;
  std::unordered_map<uint64_t, size_t> outputs;
};

template<typename T> static bool read(T &t, FILE *f)
{
  if (fread(&t, sizeof(T), 1, f) != 1)
    return false;
  return true;
}

int main(int argc, char **argv)
{
  FILE *f;
  Chain chain;

  if (argc != 2)
  {
    fprintf(stderr, "usage: %s <filename>\n", argv[0]);
    return 1;
  }

  f = fopen(argv[1], "r");
  if (!f)
  {
    fprintf(stderr, "error opening %s: %s\n", argv[1], strerror(errno));
    return 1;
  }
  uint64_t n_rct = 0, height = 0;
  while (!feof(f))
  {
    uint64_t n_ins, n_outs, idx;
    if (!read(height, f))
    {
      if (feof(f))
        break;
      goto read_fail;
    }
    chain.txs.resize(chain.txs.size() + 1);
    Transaction &tx = chain.txs.back();
    tx.height = height;
    if (!read(n_ins, f))
      goto read_fail;
    if (!read(n_outs, f))
      goto read_fail;
    for (size_t n = 0; n < n_ins; ++n)
    {
      if (!read(idx, f))
        goto read_fail;
      tx.inputs.push_back(idx);
      if (idx >= n_rct)
      {
        printf("Bad idx: %lu >= %lu\n", idx, n_rct);
        return 1;
      }
      chain.inputs.emplace(idx, chain.txs.size() - 1);
    }
    for (size_t n = 0; n < n_outs; ++n)
    {
      if (!read(idx, f))
        goto read_fail;
      tx.outputs.push_back(idx);
      chain.outputs.emplace(idx, chain.txs.size() - 1);
      ++n_rct;
    }
    //if (n_rct > 50000) break; //////////////////////////
  }
  fclose(f);

  printf("%lu txes with rct ins/outs\n", chain.txs.size());
  printf("%lu rct outs\n", n_rct);

  if (0)
  {
    std::vector<size_t> counts(4096, 0);
    size_t max_count = 0;
    for (uint64_t idx = 0; idx < n_rct; ++idx)
    {
      size_t count = chain.inputs.count(idx);
      max_count = std::max(max_count, count);
      if (count < counts.size())
        counts[count]++;
      else
        printf("Output %lu is used %zu times, more than expected\n", idx, count);
    }
    for (size_t n = 0; n <= std::min(max_count, counts.size() - 1); ++n)
    {
      printf("Used %zu times: %zu (%.1f%%)\n", n, counts[n], 100.0f * counts[n] / n_rct);
    }
  }

  if (1)
  {
    std::vector<size_t> output_lengths(n_rct, 0);
    for (const auto &tx: chain.txs)
    {
      const uint64_t input_height = tx.height;
      for (uint64_t in_idx: tx.inputs)
      {
        const uint64_t output_height = chain.txs[chain.outputs[in_idx]].height;
        if (output_height + 10 <= input_height && output_height + (uint64_t)(720*1.8f) > input_height)
        {
          for (uint64_t out_idx: tx.outputs)
            output_lengths[out_idx] = output_lengths[in_idx] + 1;
        }
      }
    }
    std::vector<size_t> lengths(4096, 0);
    size_t max_length = 0, chains = 0, possible_chains= 0;
    for (size_t n = output_lengths.size() - 50000; n < output_lengths.size() - 40000; ++n)
    //for (size_t n = 0; n < output_lengths.size(); ++n)
    {
      max_length = std::max(max_length, output_lengths[n]);
      if (output_lengths[n] >= 4096)
        printf("%zu length chain found\n", output_lengths[n]);
      else
        ++lengths[output_lengths[n]];
      if (output_lengths[n] > 0)
        ++chains;
      ++possible_chains;
    }
    for (size_t n = 1; n < std::min((size_t)4096, max_length); ++n)
    {
      printf("%zu chains of length %zu\n", lengths[n], n);
    }
    printf("%zu/%zu chains found (%.1f%%)\n", chains, possible_chains, 100.0f * chains / possible_chains);
  }

  return 0;

read_fail:
  fprintf(stderr, "error reading from %s: %s\n", argv[1], strerror(errno));
  fclose(f);
  return 1;
}
