const { Record } = require('bns/lib/wire');

// TODO: parse other sections also, not just answer and authority
function parseDelvOutput(output) {
  const results = [];

  const fetchRegex = /;; fetch:.+?\n(.+?\n\n\n)/gs;
  let fetchMatch;

  while ((fetchMatch = fetchRegex.exec(output)) != null) {
    const fetchOutput = fetchMatch[1];
    const result = { answer: [], authority: [] };

    // extract sections from the output
    const sectionRegex = /;; (ANSWER|AUTHORITY) SECTION:\s+(.*?)(?=;;|\n$)/gs;
    let sectionMatch;

    while ((sectionMatch = sectionRegex.exec(fetchOutput)) != null) {
      // Only take these 2 sections
      const sectionType = sectionMatch[1].toLowerCase();
      if (!["answer", "authority"].includes(sectionType)) continue;

      // Extract records from section
      const recordRegex = /^;(\S+)\s+(\d+)\s+IN\s+(\S+)\s+(.*)$((?:\s+;\s+(?:.*))*)$/gm;
      let recordMatch;

      while ((recordMatch = recordRegex.exec(sectionMatch[2])) !== null) {
        let value = recordMatch[5].replace(/\s+\(/g, '');
        if (recordMatch[6]) {
          value += recordMatch[6].replace(/;\s+|\n|\(|(?:\s*\).*)/g, '');
        }

        // Parse record and store it
        const recordStr = recordMatch.slice(1).join(' ').replaceAll(/^;/gm, '');
        const record = new Record();
        record.fromString(recordStr);
        result[sectionType].push(record);
      }
    }

    results.push(result);
  }

  return results;
}

exports.parseDelvOutput = parseDelvOutput;
