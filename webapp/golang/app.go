package main

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "net/http/pprof"
	"runtime"
	"runtime/pprof"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"github.com/jmoiron/sqlx"
	"github.com/zenazn/goji"
	"github.com/zenazn/goji/web"
	"github.com/zenazn/goji/web/middleware"
)

var (
	cpuProfileFile   = "/tmp/cpu.pprof"
	memProfileFile   = "/tmp/mem.pprof"
	blockProfileFile = "/tmp/block.pprof"
)

var (
	db    *sqlx.DB
	store *sessions.CookieStore
	fnc   = flag.String("func", "default", "")
)

const (
	postsPerPage   = 20
	ISO8601_FORMAT = "2006-01-02T15:04:05-07:00"
	UploadLimit    = 10 * 1024 * 1024 // 10mb

	// CSRF Token error
	StatusUnprocessableEntity = 422
	imagePath                 = "/home/isucon/work/webapp/image"
)

type User struct {
	ID          int       `db:"id"`
	AccountName string    `db:"account_name"`
	Passhash    string    `db:"passhash"`
	Authority   int       `db:"authority"`
	DelFlg      int       `db:"del_flg"`
	CreatedAt   time.Time `db:"created_at"`
}

type Post struct {
	ID           int       `db:"id"`
	UserID       int       `db:"user_id"`
	AccountName  string    `db:"account_name"`
	Imgdata      []byte    `db:"imgdata"`
	Body         string    `db:"body"`
	Mime         string    `db:"mime"`
	CreatedAt    time.Time `db:"created_at"`
	CommentCount int
	Comments     []Comment
	User         User
	CSRFToken    string
}

type Comment struct {
	ID          int       `db:"id"`
	PostID      int       `db:"post_id"`
	UserID      int       `db:"user_id"`
	AccountName string    `db:"account_name"`
	Comment     string    `db:"comment"`
	CreatedAt   time.Time `db:"created_at"`
	User        User
}

var userCacheMtx sync.Mutex
var userCache map[string]User

var commentCacheMtx sync.Mutex
var commentCache map[int][]Comment

func init() {
	store = sessions.NewCookieStore([]byte("sendagaya"))
	userCache = map[string]User{}
	commentCache = map[int][]Comment{}
}

func imageInitialize() {
	os.MkdirAll(imagePath, 0777)

	files, err := ioutil.ReadDir(imagePath + "/")
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range files {
		var id int
		var ext string
		fmt.Sscanf(file.Name(), "%d.%s", &id, &ext)
		if id > 10000 {
			os.Remove(file.Name())
		}
	}

	/*
		for id := 0; id <= 10000; id += 50 {
			var posts []Post
			err := db.Select(&posts, "SELECT * FROM `posts` WHERE id > ? AND id <= ?", id, id+50)
			if err != nil {
				fmt.Println(err.Error())
				return
			}
			for _, post := range posts {
				ext := ""
				if post.Mime == "image/jpeg" {
					ext = "jpg"
				} else if post.Mime == "image/png" {
					ext = "png"
				} else if post.Mime == "image/gif" {
					ext = "gif"
				}
				path := imagePath + "/" + fmt.Sprint(post.ID) + "." + ext
				if _, err := os.Stat(path); os.IsNotExist(err) {
					err = ioutil.WriteFile(path, post.Imgdata, 0777)
					if err != nil {
						fmt.Println("Image WriteError", err)
						return
					}
				}
			}
		}
	*/
}

func memInitialize() {
	/*
		PostDB = make([]int, 0, 20000)

		var results []Post
		err := db.Select(&results, "SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts`")
		mtxPostDB.Lock()
		PostDB = append(PostDB, results...)
		mtxPostDB.Unlock()
	*/
}

func dbInitialize() {
	sqls := []string{
		"DELETE FROM users WHERE id > 1000",
		"DELETE FROM posts WHERE id > 10000",
		"DELETE FROM comments WHERE id > 100000",
		"UPDATE users SET del_flg = 0",
		"UPDATE users SET del_flg = 1 WHERE id % 50 = 0",
	}

	for _, sql := range sqls {
		db.Exec(sql)
	}
}

func tryLogin(accountName, password string) *User {
	u := User{}
	err := db.Get(&u, "SELECT * FROM users WHERE account_name = ? AND del_flg = 0", accountName)
	if err != nil {
		return nil
	}

	if &u != nil && calculatePasshash(u.AccountName, password) == u.Passhash {
		return &u
	} else if &u == nil {
		return nil
	} else {
		return nil
	}
}

var regexpName = regexp.MustCompile("\\A[0-9a-zA-Z_]{3,}\\z")
var regexpPass = regexp.MustCompile("\\A[0-9a-zA-Z_]{6,}\\z")

func validateUser(accountName, password string) bool {
	return regexpName.MatchString(accountName) && regexpPass.MatchString(password)
}

func digest(src string) string {
	s := sha512.New()
	io.WriteString(s, src)
	return hex.EncodeToString(s.Sum(nil))
}

func calculateSalt(accountName string) string {
	return digest(accountName)
}

func calculatePasshash(accountName, password string) string {
	return digest(password + ":" + calculateSalt(accountName))
}

func getSession(r *http.Request) *sessions.Session {
	session, _ := store.Get(r, "isuconp-go.session")
	return session
}

func getSessionUser(r *http.Request) User {
	session := getSession(r)
	uid, ok := session.Values["user_id"]
	if !ok || uid == nil {
		return User{}
	}
	uids := fmt.Sprint(uid)

	userCacheMtx.Lock()
	user, ok := userCache[uids]
	userCacheMtx.Unlock()

	if ok {
		return user
	}
	u := User{}
	err := db.Get(&u, "SELECT * FROM `users` WHERE `id` = ?", uid)
	if err != nil {
		return User{}
	}

	userCacheMtx.Lock()
	userCache[uids] = u
	userCacheMtx.Unlock()
	return u
}

func getFlash(w http.ResponseWriter, r *http.Request, key string) string {
	session := getSession(r)
	value, ok := session.Values[key]

	if !ok || value == nil {
		return ""
	} else {
		delete(session.Values, key)
		session.Save(r, w)
		return value.(string)
	}
}

func makePosts2(results []Post, CSRFToken string, allComments bool) ([]Post, error) {
	for i, p := range results {
		commentCacheMtx.Lock()
		coms, ok := commentCache[p.ID]
		commentCacheMtx.Unlock()

		if ok {
			p.Comments = coms
			p.CommentCount = len(coms)
		} else {
			query := "SELECT * FROM `comments` WHERE `post_id` = ? ORDER BY `created_at` ASC"
			var comments []Comment
			cerr := db.Select(&comments, query, p.ID)
			if cerr != nil {
				return nil, cerr
			}
			for i := 0; i < len(comments); i++ {
				comments[i].User.AccountName = comments[i].AccountName
			}
			p.CommentCount = len(comments)
			p.Comments = comments
			commentCacheMtx.Lock()
			commentCache[p.ID] = comments
			commentCacheMtx.Unlock()
		}
		p.CSRFToken = CSRFToken
		results[i] = p
	}
	return results, nil
}

func makePosts(results []Post, CSRFToken string, allComments bool) ([]Post, error) {
	var posts []Post

	for _, p := range results {
		err := db.Get(&p.CommentCount, "SELECT COUNT(*) AS `count` FROM `comments` WHERE `post_id` = ?", p.ID)
		if err != nil {
			return nil, err
		}

		query := "SELECT * FROM `comments` WHERE `post_id` = ? ORDER BY `created_at` DESC"
		if !allComments {
			query += " LIMIT 3"
		}

		var comments []Comment
		cerr := db.Select(&comments, query, p.ID)
		if cerr != nil {
			return nil, cerr
		}

		for i := 0; i < len(comments); i++ {
			uerr := db.Get(&comments[i].User, "SELECT * FROM `users` WHERE `id` = ?", comments[i].UserID)
			if uerr != nil {
				return nil, uerr
			}
		}

		// reverse
		for i, j := 0, len(comments)-1; i < j; i, j = i+1, j-1 {
			comments[i], comments[j] = comments[j], comments[i]
		}

		p.Comments = comments
		/*
			perr := db.Get(&p.User, "SELECT * FROM `users` WHERE `id` = ?", p.UserID)
			if perr != nil {
				return nil, perr
			}
		*/
		p.CSRFToken = CSRFToken

		if p.User.DelFlg == 0 {
			posts = append(posts, p)
		}
		if len(posts) >= postsPerPage {
			break
		}
	}

	return posts, nil
}

func imageURL(p Post) string {
	ext := ""
	if p.Mime == "image/jpeg" {
		ext = ".jpg"
	} else if p.Mime == "image/png" {
		ext = ".png"
	} else if p.Mime == "image/gif" {
		ext = ".gif"
	}

	return "/image/" + strconv.Itoa(p.ID) + ext
}

func isLogin(u User) bool {
	return u.ID != 0
}

func getCSRFToken(r *http.Request) string {
	session := getSession(r)
	csrfToken, ok := session.Values["csrf_token"]
	if !ok {
		return ""
	}
	return csrfToken.(string)
}

func secureRandomStr(b int) string {
	k := make([]byte, b)
	if _, err := io.ReadFull(crand.Reader, k); err != nil {
		panic("error reading from random source: " + err.Error())
	}
	return hex.EncodeToString(k)
}

func getTemplPath(filename string) string {
	return path.Join("templates", filename)
}

func getInitialize(w http.ResponseWriter, r *http.Request) {
	dbInitialize()
	imageInitialize()
	memInitialize()
	updateIndexPosts()
	w.WriteHeader(http.StatusOK)
}

var loginTemplate = template.Must(template.ParseFiles(
	getTemplPath("layout.html"),
	getTemplPath("login.html")))

func getLogin(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)

	if isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	loginTemplate.Execute(w, struct {
		Me    User
		Flash string
	}{me, getFlash(w, r, "notice")})
}

func postLogin(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	u := tryLogin(r.FormValue("account_name"), r.FormValue("password"))

	if u != nil {
		session := getSession(r)
		session.Values["user_id"] = u.ID
		session.Values["csrf_token"] = secureRandomStr(16)
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
	} else {
		session := getSession(r)
		session.Values["notice"] = "アカウント名かパスワードが間違っています"
		session.Save(r, w)

		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func getRegister(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("register.html")),
	).Execute(w, struct {
		Me    User
		Flash string
	}{User{}, getFlash(w, r, "notice")})
}

func postRegister(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	accountName, password := r.FormValue("account_name"), r.FormValue("password")

	validated := validateUser(accountName, password)
	if !validated {
		session := getSession(r)
		session.Values["notice"] = "アカウント名は3文字以上、パスワードは6文字以上である必要があります"
		session.Save(r, w)

		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	exists := 0
	// ユーザーが存在しない場合はエラーになるのでエラーチェックはしない
	db.Get(&exists, "SELECT 1 FROM users WHERE `account_name` = ?", accountName)

	if exists == 1 {
		session := getSession(r)
		session.Values["notice"] = "アカウント名がすでに使われています"
		session.Save(r, w)

		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	query := "INSERT INTO `users` (`account_name`, `passhash`) VALUES (?,?)"
	result, eerr := db.Exec(query, accountName, calculatePasshash(accountName, password))
	if eerr != nil {
		fmt.Println(eerr.Error())
		return
	}

	session := getSession(r)
	uid, lerr := result.LastInsertId()
	if lerr != nil {
		fmt.Println(lerr.Error())
		return
	}
	session.Values["user_id"] = uid
	session.Values["csrf_token"] = secureRandomStr(16)
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

func getLogout(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	delete(session.Values, "user_id")
	session.Options = &sessions.Options{MaxAge: -1}
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

var getIndexPostsMtx sync.RWMutex
var getIndexPosts []Post
var getIndexPostsContent string

func updateIndexPosts() bool {
	foo := []Post{}
	err := db.Select(&foo, "SELECT posts.id, posts.user_id, posts.body, posts.mime, posts.created_at, posts.account_name FROM `posts` AS posts INNER JOIN `users` ON user_id = users.id WHERE users.del_flg = 0 ORDER BY `created_at` DESC LIMIT ?", postsPerPage)
	if err != nil {
		fmt.Println(err)
		return false
	}

	posts, merr := makePosts2(foo, "[[[CSRFTOKEN]]]", false)
	if merr != nil {
		fmt.Println(merr)
		return false
	}

	var b bytes.Buffer
	IndexTemplate.Execute(&b, struct {
		Posts     []Post
		CSRFToken string
	}{posts, "[[[CSRFTOKEN]]]"})

	getIndexPostsMtx.Lock()
	getIndexPosts = foo
	getIndexPostsContent = b.String()
	getIndexPostsMtx.Unlock()

	return true
}

var fmap = template.FuncMap{
	"imageURL": imageURL,
}

var IndexTemplate = template.Must(
	template.New("index.html").Funcs(fmap).ParseFiles(
		getTemplPath("index.html"),
		getTemplPath("posts.html"),
		getTemplPath("post.html")))

var IndexTemplateTop, _ = template.New("index").Parse(`<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Iscogram</title>
    <link href="/css/style.css" media="screen" rel="stylesheet" type="text/css">
  </head>
  <body>
    <div class="container">
      <div class="header">
        <div class="isu-title">
          <h1><a href="/">Iscogram</a></h1>
        </div>
        <div class="isu-header-menu">
          {{ if eq .Me.ID 0}}
          <div><a href="/login">ログイン</a></div>
          {{ else }}
          <div><a href="/@{{.Me.AccountName}}"><span class="isu-account-name">{{.Me.AccountName}}</span>さん</a></div>
          {{ if eq .Me.Authority 1 }}
          <div><a href="/admin/banned">管理者用ページ</a></div>
          {{ end }}
          <div><a href="/logout">ログアウト</a></div>
          {{ end }}
        </div>
      </div>
<div class="isu-submit">
  <form method="post" action="/" enctype="multipart/form-data">
    <div class="isu-form">
      <input type="file" name="file" value="file">
    </div>
    <div class="isu-form">
      <textarea name="body"></textarea>
    </div>
    <div class="form-submit">
      <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
      <input type="submit" name="submit" value="submit">
    </div>
    {{if .Flash}}
    <div id="notice-message" class="alert alert-danger">
      {{.Flash}}
    </div>
    {{end}}
  </form>
</div>
`)

var IndexTemplateContTopBottom = []byte(`
<div id="isu-post-more">
  <button id="isu-post-more-btn">もっと見る</button>
  <img class="isu-loading-icon" src="/img/ajax-loader.gif">
</div>
    </div>
    <script src="/js/jquery-2.2.0.js"></script>
    <script src="/js/jquery.timeago.js"></script>
    <script src="/js/jquery.timeago.ja.js"></script>
    <script src="/js/main.js"></script>
  </body>
</html>
`)

func getIndex(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)

	IndexTemplateTop.Execute(w, struct {
		Me        User
		Flash     string
		CSRFToken string
	}{me, getFlash(w, r, "notice"), getCSRFToken(r)})

	getIndexPostsMtx.RLock()
	a := strings.Replace(getIndexPostsContent, "[[[CSRFTOKEN]]]", getCSRFToken(r), 30)
	getIndexPostsMtx.RUnlock()

	w.Write([]byte(a))

	w.Write(IndexTemplateContTopBottom)
}

var accountNameTemplate = template.Must(template.New("layout.html").Funcs(fmap).ParseFiles(
	getTemplPath("layout.html"),
	getTemplPath("user.html"),
	getTemplPath("posts.html"),
	getTemplPath("post.html")))

func getAccountName(c web.C, w http.ResponseWriter, r *http.Request) {
	user := User{}
	uerr := db.Get(&user, "SELECT * FROM `users` WHERE `account_name` = ? AND `del_flg` = 0", c.URLParams["accountName"])

	if uerr != nil {
		fmt.Println(uerr)
		return
	}

	if user.ID == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	results := []Post{}

	rerr := db.Select(&results, "SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` WHERE `user_id` = ? ORDER BY `created_at` DESC LIMIT ?", user.ID, postsPerPage)
	if rerr != nil {
		fmt.Println(rerr)
		return
	}

	posts, merr := makePosts2(results, getCSRFToken(r), false)
	if merr != nil {
		fmt.Println(merr)
		return
	}

	commentCount := 0
	cerr := db.Get(&commentCount, "SELECT COUNT(*) AS count FROM `comments` WHERE `user_id` = ?", user.ID)
	if cerr != nil {
		fmt.Println(cerr)
		return
	}

	postIDs := []int{}
	perr := db.Select(&postIDs, "SELECT `id` FROM `posts` WHERE `user_id` = ?", user.ID)
	if perr != nil {
		fmt.Println(perr)
		return
	}
	postCount := len(postIDs)

	commentedCount := 0
	if postCount > 0 {
		s := []string{}
		for range postIDs {
			s = append(s, "?")
		}
		placeholder := strings.Join(s, ", ")

		// convert []int -> []interface{}
		args := make([]interface{}, len(postIDs))
		for i, v := range postIDs {
			args[i] = v
		}

		ccerr := db.Get(&commentedCount, "SELECT COUNT(*) AS count FROM `comments` WHERE `post_id` IN ("+placeholder+")", args...)
		if ccerr != nil {
			fmt.Println(ccerr)
			return
		}
	}

	me := getSessionUser(r)

	accountNameTemplate.Execute(w, struct {
		Posts          []Post
		User           User
		PostCount      int
		CommentCount   int
		CommentedCount int
		Me             User
	}{posts, user, postCount, commentCount, commentedCount, me})
}

var getPostsTemplate = template.Must(template.New("posts.html").Funcs(fmap).ParseFiles(
	getTemplPath("posts.html"),
	getTemplPath("post.html")))

func getPosts(w http.ResponseWriter, r *http.Request) {
	m, parseErr := url.ParseQuery(r.URL.RawQuery)
	if parseErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Println(parseErr)
		return
	}

	maxCreatedAt := m.Get("max_created_at")
	if maxCreatedAt == "" {
		return
	}

	//t, terr := time.Parse(ISO8601_FORMAT, maxCreatedAt)
	//if terr != nil {
	//	fmt.Println(terr)
	//	return
	//}
	/*
		results := []Post{}
		rerr := db.Select(&results, "SELECT `id`, `user_id`, `body`, `mime`, `created_at`, `account_name` FROM `posts` WHERE `created_at` <= ? ORDER BY `created_at` DESC", t.Format(ISO8601_FORMAT))
		if rerr != nil {
			fmt.Println(rerr)
			return
		}
	*/

	getIndexPostsMtx.RLock()
	results := getIndexPosts
	getIndexPostsMtx.RUnlock()

	if len(results) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	posts, merr := makePosts2(results, getCSRFToken(r), false)
	if merr != nil {
		fmt.Println(merr)
		return
	}

	if len(posts) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	getPostsTemplate.Execute(w, posts)
}

var getPostsIDTemplate = template.Must(template.New("layout.html").Funcs(fmap).ParseFiles(
	getTemplPath("layout.html"),
	getTemplPath("post_id.html"),
	getTemplPath("post.html")))

func getPostsID(c web.C, w http.ResponseWriter, r *http.Request) {
	pid, err := strconv.Atoi(c.URLParams["id"])
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	results := []Post{}
	rerr := db.Select(&results, "SELECT * FROM `posts` WHERE `id` = ?", pid)
	if rerr != nil {
		fmt.Println(rerr)
		return
	}

	posts, merr := makePosts(results, getCSRFToken(r), true)
	if merr != nil {
		fmt.Println(merr)
		return
	}

	if len(posts) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	p := posts[0]

	me := getSessionUser(r)

	getPostsIDTemplate.Execute(w, struct {
		Post Post
		Me   User
	}{p, me})
}

func postIndex(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(4096)

	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(StatusUnprocessableEntity)
		return
	}

	file, header, ferr := r.FormFile("file")
	if ferr != nil {
		session := getSession(r)
		session.Values["notice"] = "画像が必須です"
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	mime := ""
	ext := ""
	if file != nil {
		// 投稿のContent-Typeからファイルのタイプを決定する
		contentType := header.Header["Content-Type"][0]
		if strings.Contains(contentType, "jpeg") {
			mime = "image/jpeg"
			ext = "jpg"
		} else if strings.Contains(contentType, "png") {
			mime = "image/png"
			ext = "png"
		} else if strings.Contains(contentType, "gif") {
			mime = "image/gif"
			ext = "gif"
		} else {
			session := getSession(r)
			session.Values["notice"] = "投稿できる画像形式はjpgとpngとgifだけです"
			session.Save(r, w)

			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}
	/*
		filedata, rerr := ioutil.ReadAll(file)
		if rerr != nil {
			fmt.Println(rerr.Error())
		}
	*/
	//if len(filedata) > UploadLimit {
	if r.ContentLength > UploadLimit {
		session := getSession(r)
		session.Values["notice"] = "ファイルサイズが大きすぎます"
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	query := "INSERT INTO `posts` (`user_id`, `mime`, `imgdata`, `body`, `account_name`) VALUES (?,?,?,?,?)"
	result, eerr := db.Exec(
		query,
		me.ID,
		mime,
		//filedata,
		[]byte{},
		r.FormValue("body"),
		me.AccountName,
	)
	if eerr != nil {
		fmt.Println(eerr.Error())
		return
	}

	pid, lerr := result.LastInsertId()
	if lerr != nil {
		fmt.Println(lerr.Error())
		return
	}

	outfile, err := os.Create(imagePath + "/" + fmt.Sprint(pid) + "." + ext)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	_, err = io.Copy(outfile, file)
	if err != nil {
		http.Error(w, "Error saving file: "+err.Error(), http.StatusBadRequest)
		return
	}
	updateIndexPosts()
	http.Redirect(w, r, "/posts/"+strconv.FormatInt(pid, 10), http.StatusFound)
	return
}

func postComment(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(StatusUnprocessableEntity)
		return
	}

	postID, ierr := strconv.Atoi(r.FormValue("post_id"))
	if ierr != nil {
		fmt.Println("post_idは整数のみです")
		return
	}

	var times []time.Time
	err := db.Select(&times, "SELECT CURRENT_TIMESTAMP();")
	if err != nil {
		fmt.Println("err", err.Error())
		return
	}
	cur := times[0]

	query := "INSERT INTO `comments` (`post_id`, `user_id`, `comment`, `account_name`, `created_at`) VALUES (?,?,?,?,?)"
	result, err := db.Exec(query, postID, me.ID, r.FormValue("comment"), me.AccountName, cur)
	if err != nil {
		fmt.Println("err", err.Error())
		return
	}

	cid, lerr := result.LastInsertId()
	if lerr != nil {
		fmt.Println(lerr.Error())
		return
	}

	commentCacheMtx.Lock()
	comms, ok := commentCache[postID]
	if ok {
		comms = append(comms, Comment{
			ID:          int(cid),
			PostID:      postID,
			UserID:      me.ID,
			AccountName: me.AccountName,
			Comment:     r.FormValue("comment"),
			CreatedAt:   cur,
			User:        me,
		})
	}
	commentCacheMtx.Unlock()

	http.Redirect(w, r, fmt.Sprintf("/posts/%d", postID), http.StatusFound)
}

func getAdminBanned(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if me.Authority == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	users := []User{}
	err := db.Select(&users, "SELECT * FROM `users` WHERE `authority` = 0 AND `del_flg` = 0 ORDER BY `created_at` DESC")
	if err != nil {
		fmt.Println(err)
		return
	}

	template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("banned.html")),
	).Execute(w, struct {
		Users     []User
		Me        User
		CSRFToken string
	}{users, me, getCSRFToken(r)})
}

func postAdminBanned(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if me.Authority == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(StatusUnprocessableEntity)
		return
	}

	query := "UPDATE `users` SET `del_flg` = ? WHERE `id` = ?"

	r.ParseForm()
	for _, id := range r.Form["uid[]"] {
		db.Exec(query, 1, id)
	}

	for _, id := range r.Form["uid[]"] {
		userCacheMtx.Lock()
		u, ok := userCache[fmt.Sprint(id)]
		if ok {
			u.DelFlg = 1
			userCache[fmt.Sprint(id)] = u
		}
		userCacheMtx.Unlock()
	}

	http.Redirect(w, r, "/admin/banned", http.StatusFound)
}

func main() {
	flag.Parse()
	log.SetOutput(ioutil.Discard)
	host := os.Getenv("ISUCONP_DB_HOST")
	if host == "" {
		host = "localhost"
	}
	port := os.Getenv("ISUCONP_DB_PORT")
	if port == "" {
		port = "3306"
	}
	_, err := strconv.Atoi(port)
	if err != nil {
		log.Fatalf("Failed to read DB port number from an environment variable ISUCONP_DB_PORT.\nError: %s", err.Error())
	}
	user := os.Getenv("ISUCONP_DB_USER")
	if user == "" {
		user = "root"
	}
	password := os.Getenv("ISUCONP_DB_PASSWORD")
	dbname := os.Getenv("ISUCONP_DB_NAME")
	if dbname == "" {
		dbname = "isuconp"
	}

	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=true&loc=Local",
		user,
		password,
		host,
		port,
		dbname,
	)

	db, err = sqlx.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("Failed to connect to DB: %s.", err.Error())
	}
	defer db.Close()

	if *fnc != "default" {
		var users []User
		err = db.Select(&users, "SELECT id, account_name FROM users")
		fmt.Println(err)
		for _, user := range users {
			//db.Exec("UPDATE `comments` SET `account_name` = ? WHERE `user_id` = ?", user.AccountName, user.ID)
			db.Exec("UPDATE `posts` SET `account_name` = ? WHERE `user_id` = ?", user.AccountName, user.ID)
		}
		return
	}

	runtime.MemProfileRate = 1024
	http.HandleFunc("/startprof", func(w http.ResponseWriter, r *http.Request) {
		f, err := os.Create(cpuProfileFile)
		if err != nil {
			w.Write([]byte(err.Error()))
			return
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			w.Write([]byte(err.Error()))
			return
		}
		runtime.SetBlockProfileRate(1) // どれくらい遅くなるか確認する
		w.Write([]byte("profile started\n"))
	})

	http.HandleFunc("/endprof", func(w http.ResponseWriter, r *http.Request) {
		pprof.StopCPUProfile()
		runtime.SetBlockProfileRate(0)
		w.Write([]byte("profile ended\n"))

		mf, err := os.Create(memProfileFile)
		if err != nil {
			w.Write([]byte(err.Error()))
			return
		}
		pprof.WriteHeapProfile(mf)

		bf, err := os.Create(blockProfileFile)
		if err != nil {
			w.Write([]byte(err.Error()))
			return
		}
		pprof.Lookup("block").WriteTo(bf, 0)
	})

	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	goji.Abandon(middleware.Logger)
	goji.Get("/initialize", getInitialize)
	goji.Get("/login", getLogin)
	goji.Post("/login", postLogin)
	goji.Get("/register", getRegister)
	goji.Post("/register", postRegister)
	goji.Get("/logout", getLogout)
	goji.Get("/", getIndex)
	goji.Get(regexp.MustCompile(`^/@(?P<accountName>[a-zA-Z]+)$`), getAccountName)
	goji.Get("/posts", getPosts)
	goji.Get("/posts/:id", getPostsID)
	goji.Post("/", postIndex)
	//goji.Get("/image/:id.:ext", getImage)
	goji.Post("/comment", postComment)
	goji.Get("/admin/banned", getAdminBanned)
	goji.Post("/admin/banned", postAdminBanned)
	//goji.Get("/*", http.FileServer(http.Dir("../public")))
	goji.Serve()
}
