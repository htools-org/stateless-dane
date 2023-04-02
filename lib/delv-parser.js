const { Record } = require('bns/lib/wire');

// TODO: parse other sections also, not just answers
function parseDelvOutput(output) {
  const results = [];

  // // extract the query name from the output
  // const queryNameRegex = /;; QUERY SECTION:\s+\S+\s+IN\s+(\S+)\s+.*?(?=\n\s*\n)/s;
  // const queryNameMatch = queryNameRegex.exec(output);
  // if (queryNameMatch) {
  //   result.queryName = queryNameMatch[1];
  // }

  // extract the answer section from the output
  const answerSectionRegex = /;; ANSWER SECTION:\s+(.*?)\n\s*\n/gs;

  while ((answerSectionMatch = answerSectionRegex.exec(output)) != null) {
    results.push({ answer: [] });
    const result = results[results.length - 1];
    if (answerSectionMatch) {
      result.answer = [];
      const answerRegex = /^;(\S+)\s+(\d+)\s+IN\s+(\S+)\s+(.*)$((?:\s+;\s+(?:.*))*)$/gm;
      let answerMatch;
      while ((answerMatch = answerRegex.exec(answerSectionMatch[1])) !== null) {
        let value = answerMatch[4].replace(/\s+\(/g, '');
        if (answerMatch[5]) {
          value += answerMatch[5].replace(/;\s+|\n|\(|(?:\s*\).*)/g, '');
        }

        const recordStr = answerMatch.slice(1).join(' ').replaceAll(/^;/gm, '');
        const record = new Record();
        record.fromString(recordStr);
        result.answer.push(record);
      }
    }
  }

  return results;
}

exports.parseDelvOutput = parseDelvOutput;
