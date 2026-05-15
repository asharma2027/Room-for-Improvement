const fs = require('fs');
const filePath = './views/explore.ejs';
const s = fs.readFileSync(filePath, 'utf8');
// Only extract the <script type="module"> ... </script>. That's where my code lives.
const re = /<script type="module">([\s\S]*?)<\/script>/;
const m = re.exec(s);
if (!m) { console.log('no module script'); process.exit(1); }
const body = m[1];
console.log('module script length:', body.length);
// Strip ES imports so we can parse with new Function
const stripped = body.replace(/^\s*import[^;]+;\s*$/gm, '');
try {
    new Function(stripped);
    console.log('module script: OK');
} catch (e) {
    console.log('module script: PARSE ERROR ' + e.message);
    // Try to find line
    const lines = stripped.split('\n');
    console.log('total lines:', lines.length);
}
