pwd=`pwd`
libc_name=`ls | grep "libc"`
elf_name=${pwd##/*/}

cat /ex.py | sed "s/elf_name/$elf_name/g" > ./ex.py
if [ $libc_name ]; then
	cat ./ex.py | sed "s/#libc/libc/g" > ./ex2.py
	cat ./ex2.py | sed "s/libc_name/$libc_name/g" > ./ex.py
	rm ./ex2.py
fi

cat /nc.sh | sed "s/elf_name/$elf_name/g" > ./nc.sh

cp /debug.py ./