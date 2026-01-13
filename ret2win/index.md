# tags: pwn, rop | origin: ROP Emporium | date: 2025-01-07
# ret2win

## Content
1. [Assessment](#Assessment)
## Assessment
From the web, we will got a zip files, access [here](https://ropemporium.com/challenge/ret2win.html), that have the flag and the binary itself.

First, We will see how the program works using IDA or any decompiler for easier analysis. I'll give the clean look of the source code down here
```C
int ret2win()
{
  puts("Well done! Here's your flag:");
  return system("/bin/cat flag.txt");
}

int pwnme()
{
  char s[32];

  memset(s, 0, sizeof(s));
  puts("For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!");
  puts("What could possibly go wrong?");
  puts("You there, may I have your input please? And don't worry about null bytes, we're using read()!\n");
  printf("> ");
  read(0, s, 56);
  return puts("Thank you!");
}

int main()
{
  setvbuf(_bss_start, 0LL, 2, 0LL);
  puts("ret2win by ROP Emporium");
  puts("x86_64\n");
  pwnme();
  puts("\nExiting");
  return 0;
}
```

This chall already implicitly tell us what to do if you read the text that its printed. Lets take a look for each vulnerability that given here.
1. Buffer Overflow
```C
char s[32];
...
read(0, s, 56);
```
As you can see, the variable `S` is initialized by having a `character` data type that have length of `32`. 
Notes that, `char` type have one bytes. That means variable `s` have the length or can contain 32 bytes.

**BUT**, `read(0, s, 56)` means we will read 56 bytes from 0, which is input (`stdin`), to `s` variable. 
`s` can only contain 32 bytes but we can input up to 56 bytes ? that means we can overwrite over the `s` can handle !

2. A function or STUB that call `system()`
So.. You can see it on the code above. There is this lines of code
```C
int ret2win()
{
  puts("Well done! Here's your flag:");
  return system("/bin/cat flag.txt");
}
```
`system()` will start new child process that run a certain command, which in this case is `/bin/cat flag.txt`.. 
Our objective is clear then, We only need to redirect the program flow from exiting normally. We forced the program to execute `retwin()`

## Exploiting
