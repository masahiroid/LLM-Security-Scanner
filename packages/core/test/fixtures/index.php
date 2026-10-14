<?php
// llmscan テスト用フィクスチャ（意図的に脆弱なコード）

$id = $_GET['id'];
$pdo = new PDO('sqlite:app.db');
$rows = $pdo->query("SELECT * FROM users WHERE id = $id"); // expect: PHP-SQLI-001
$rows = $pdo->query('SELECT * FROM users WHERE id = ' . $id); // expect: PHP-SQLI-001
$res = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_POST['id']); // expect: PHP-SQLI-001
// 安全：プリペアドステートメント
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
$stmt->execute([$id]);
// 安全：整数にキャスト
$rows = $pdo->query('SELECT * FROM users WHERE id = ' . (int)$id);
$rows = $pdo->query('SELECT * FROM users WHERE id = ' . intval($id));

$name = $_GET['name'] ?? '';
echo "<p>Hello, $name</p>"; // expect: PHP-XSS-001
echo '<p>Hello, ' . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . '</p>';
?>
<p><?= $name ?></p><!-- expect: PHP-XSS-001 -->
<p><?= htmlspecialchars($name) ?></p>
<?php

$host = $_REQUEST['host'];
system('ping -c 1 ' . $host); // expect: PHP-CMDI-001
system('ping -c 1 ' . escapeshellarg($host));
$out = `nslookup $host`; // expect: PHP-CMDI-001

eval('return ' . $_POST['expr'] . ';'); // expect: PHP-CODEI-001
$data = unserialize($_COOKIE['cart']); // expect: PHP-DESER-001
include $_GET['page'] . '.php'; // expect: PHP-FILEINC-001
include basename($_GET['page']) . '.php';

function lab_mode(): string
{
    $m = $_COOKIE['mode'] ?? 'vuln';
    return in_array($m, ['vuln', 'secure'], true) ? $m : 'vuln';
}
echo '<span class="' . lab_mode() . '">';

function get_keyword(): string
{
    return trim($_GET['kw'] ?? '');
}
echo '<p>' . get_keyword() . '</p>'; // expect: PHP-XSS-001

function h(string $s): string
{
    return htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
}
echo '<p>' . h($_GET['kw']) . '</p>';

class UserController
{
    public function show(Request $request)
    {
        $sort = $request->input('sort');
        return DB::select('SELECT * FROM users ORDER BY ' . $sort); // expect: PHP-SQLI-001
    }

    public function ask(string $question)
    {
        $result = $this->client->chat()->create(['model' => 'gpt-4o', 'messages' => [['role' => 'user', 'content' => $question]]]);
        $sql = $result->choices[0]->message->content;
        return $this->pdo->query($sql); // expect: LLM05-SQLI-001
    }

    public function byId(int $id)
    {
        // 型宣言で int に限定されているため安全
        return $this->pdo->query('SELECT * FROM users WHERE id = ' . $id);
    }
}
