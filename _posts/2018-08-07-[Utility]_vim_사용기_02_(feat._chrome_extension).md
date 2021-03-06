---
layout: post
title: "[Utility] vim 사용기 02 (Feat. chrome extension)"
date: 2018-08-07 04:44
categories: "[Utility]"
tags: rotles98
---

저는 `youtube premium`을 사용해요. 동영상 시청뿐만 아니라 노래도 유튜브로 듣는데 특히 저는 앨범 단위로 플레이 리스트를 저장해놓고 들어요!

**A**앨범을 듣고 **B**앨범을 들으려면 직접 가서 바꿔줘야하고 **A - B - C** 듣다가 **A - C - B** 듣고 싶기도 했어요.

대충 찾아봤는데 그런 확장 프로그램은 없어서 제가 만들려했어요.

- - -
# 0x00. 분석

우선 유튜브 재생목록 창에서 개발자 모드로 플레이 리스트가 모여있는 부분의 코드를 찾았어요.

{: refdef: style="text-align: center;"}
![Playlist](/img/Utility/02/01.png)
{: refdef}

{: refdef: style="text-align: center;"}
![Playlist_code](/img/Utility/02/02.png)
{: refdef}

그리고 플레이 리스트 재생을 누르면 나오는 링크를 복사했어요.

> **https://www.youtube.com/watch?v=eFiAHhe-jNQ&list=PLYL4M5X8tfxr9TOWGnd9BvUteD7H0qGS6J**

이제 코드 주변에서 링크를 찾다보니까 아래 부분을 찾았어요.

{: refdef: style="text-align: center;"}
![Playlist_link](/img/Utility/02/03.png)
{: refdef}

- - -
# 0x01. 코딩

대충 찾아보니까 자바스크립트로 짜야하는거 같더라구요.

그래서 생활코딩에서 크롬 확장 기능 만드는거 보고 대충 따라서 짰어요.

[링크](https://opentutorials.org/course/2897/14051)

```
var body = document.querySelector("body").innerHTML;
var start = [];
var list = [];
var index = 0;

var func = function get_start(body, index)
{
	return body.indexOf("/watch", index);
}

while(func(body, index) != -1)
{
	start.push(func(body, index));
	index = func(body, index) + 1;

	if(func(body, index) != -1)
	{
		index = func(body, index) + 1;
	}
	else
	{
		break;
	}
}

for(a of start)
{
	list.push(body.substring(a, body.indexOf("\"", a+1)));
}
```

{: refdef: style="text-align: center;"}
![YAP](/img/Utility/02/04.png)
{: refdef}

실제로 콘솔에서 실행시키면 똑디 나오는걸 볼 수 있어요.

그래서 `manifest.json`, `popup.html`도 대충대충 해서 테스트를 돌리니까 안돼요... ?

뭐지 `body`가 이상한가 싶어서 `alert(body)`하니까 잘 나와요.

{: refdef: style="text-align: center;"}
![body](/img/Utility/02/05.png)
{: refdef}

디버깅 창으로 보니까 `indexOf`가 이상한거 같아서 정상적인 값이 나오는지 확인하려고 `alert(body.indexOf("\""))`를 넣고 돌려봤어요.

{: refdef: style="text-align: center;"}
![wtf](/img/Utility/02/06.png)
{: refdef}

??? 왜 **-1**이 나오지

으어어어어

- - -
# 0x02. index.vim

```
set number
set shiftwidth=4
set tabstop=4

syntax on

let g:airline_theme='hybrid'
let g:indentLine_setColors = 0

map <F2> :NERDTreeToggle<cr>
autocmd VimEnter * if !argc() | NERDTree | endif

nmap <F9> :SCCompile<cr>
nmap <F10> :SCCompileRun<cr>

call plug#begin('~/.vim/plugged')
Plug 'dennougorilla/azuki.vim' " color scheme
Plug '/usr/local/opt/fzf' " fzf
Plug 'junegunn/fzf.vim' " fzf
Plug 'Yggdroot/indentLine' " vertical lines
Plug 'scrooloose/nerdtree' " file tree
Plug 'mtth/scratch.vim' " memo
Plug 'xuhdev/SingleCompile' " compile in vim
Plug 'vim-airline/vim-airline' " status
Plug 'vim-airline/vim-airline-themes' " status theme
Plug 'easymotion/vim-easymotion' " cursor
Plug 'pangloss/vim-javascript' " javascript syntax
Plug 'plasticboy/vim-markdown' " markdown syntax
Plug 'christoomey/vim-tmux-navigator' " tmux window
call plug#end()

colorscheme azuki
```

- - -
# 0x03. vim-easymotion

코딩이나 포스팅 다 `vim`으로 했는데 플러그인중에 제일 잘 쓰는게 `vim-easymotion`이에요.

물론 많은 기능을 다 쓰고있진 않아요.

사용법은 **\\** 두 번 누르고 **f, F, t, T** 누른 후에 검색할 위치의 문자 하나만 입력하면 돼요.

**f**는 문자 앞에 커서가 위치하고 **t**는 문자 뒤에 커서가 위치해요.

**소문자**는 커서 기준 아래로 검색하고 **대문자**는 커서 기준 위로 검색해요.

{: refdef: style="text-align: center;"}
![ez_motion_01](/img/Utility/02/07.png)
{: refdef}

{: refdef: style="text-align: center;"}
![ez_motion.02](/img/Utility/02/08.png)
{: refdef}

저렇게 검색을 하면 해당 위치에 색칠된 다른 문자가 생기는데 그 문자를 누르면 커서가 이동하는 방식이에요.

