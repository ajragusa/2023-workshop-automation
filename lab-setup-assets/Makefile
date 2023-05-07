# .phony: gen

FILES=$(wildcard workshop[0-9]*.clab.yml)

gen: clean
	/srv/clab/venv/bin/python gen-topo.py

deploy: gen
	for name in workshop[0-9]*.clab.yml; do\
		containerlab deploy --reconfigure -t $${name};\
		# sleep 20;\
	done

destroy:
	for name in workshop[0-9]*.clab.yml; do\
		containerlab destroy --cleanup -t $${name};\
		# sleep 10;\
	done
	rm -rf $(wildcard clab-automation-workshop-[0-9]*)

inspect:
	for name in workshop[0-9]*.clab.yml; do\
		containerlab inspect -t $${name};\
	done

container:
	docker build -t internet2/getting_started -f Containerfile .

clean:
	rm -rf $(FILES)
