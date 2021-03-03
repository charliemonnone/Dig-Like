import os, socket, sys, time, timeit 
import dns.query, dns.message, dns.rdatatype, dns.rdataclass
from datetime import date

# ---------- Root Servers ----------
a_root = ["a.root-servers.net", "198.41.0.4"  , 	"2001:503:ba3e::2:30" 	"Verisign, Inc."]
b_root = ["b.root-servers.net", "199.9.14.201", 	"2001:500:200::b" 		"University of Southern California"]
c_root = ["c.root-servers.net", "192.33.4.12" ,		"2001:500:2::c" 		"Cogent Communications"]
d_root = ["d.root-servers.net", "199.7.91.13" ,   	"2001:500:2d::d" 		"University of Maryland"]
e_root = ["e.root-servers.net", "192.203.230.10",	"2001:500:a8::e" 		"NASA (Ames Research Center)"]
f_root = ["f.root-servers.net", "192.5.5.241", 		"2001:500:2f::f" 		"Internet Systems Consortium, Inc."]
g_root = ["g.root-servers.net", "192.112.36.4", 	"2001:500:12::d0d" 		"US Department of Defense (NIC)"]
h_root = ["h.root-servers.net", "198.97.190.53", 	"2001:500:1::53" 		"US Army (Research Lab)"]
i_root = ["i.root-servers.net", "192.36.148.17", 	"2001:7fe::53" 			"Netnod"]
j_root = ["j.root-servers.net", "192.58.128.30", 	"2001:503:c27::2:30" 	"Verisign, Inc."]
k_root = ["k.root-servers.net", "193.0.14.129", 	"2001:7fd::1" 			"RIPE NCC"]
l_root = ["l.root-servers.net", "199.7.83.42", 		"2001:500:9f::42" 		"ICANN"]
m_root = ["m.root-servers.net", "202.12.27.33", 	"2001:dc3::35" 			"WIDE Project"]


# ---------- Constants ----------
A_RECORD = int(dns.rdatatype.A)
CNAME_RECORD = int(dns.rdatatype.CNAME)
RESOLVE_CNAME = True
PRINT_TO_FILE = False

		
def formatted_resp(resp, elapsed):
	output = """QUESTION SECTION:\n{}\n\nANSWER SECTION:\n{}\n\nQuery time: {} msec\nWHEN: {} {} {}""".format(
		resp.question[0], resp.answer[0], elapsed * 1000, date.today(), time.strftime('%H:%M:%S'), time.tzname[0])
	return output

def print_to_output_file(output, domain_name):
	f = open('mydig_output.txt', 'w')
	f.write("Mydig input: {}\n\n".format(domain_name))
	f.write(output)
	f.close()
	return


def generate_query(domain_name):
	query = dns.message.make_query(qname = domain_name, rdtype = dns.rdatatype.ANY)
	return query

def resolve_request(domain_name):
	question = generate_query(domain_name)
	where = a_root[1]	# ipv4 of verisign root server
	timeout = 20

	time_start = time.process_time()	# begin timing query 
	(resp, tcp) = dns.query.udp_with_fallback(q = question, where = where, timeout = timeout, ignore_trailing = True)

	while(resp.additional != [] ):	# keep making requests until an answer or max attempts exhausted
		additional = resp.additional
		for entry in additional:
			if entry.rdtype == A_RECORD:	# use the first available ipv4 address from additional section
					where = str(entry[0])	# as the next where parameter 
					break
		(resp, tcp) = dns.query.udp_with_fallback(q = question, where = where, timeout = timeout, ignore_trailing = True)


	time_end = time.process_time()	# end timer
	elapsed = time_end - time_start	# calculate msec since first query

	if(resp.answer[0].rdtype == CNAME_RECORD and RESOLVE_CNAME):	# if enabled handle CNAME resolution via recursive call
		# print("CNAME returned, resolving CNAME...")
		resolve_request(str(resp.answer[0][0]))
	else:
		output = formatted_resp(resp, elapsed)	# get the formatted output
		print(output)	


	if(PRINT_TO_FILE):
		print_to_output_file(output, domain_name) 
	

# TODO: suss out why timing could return 0, is the machine caching? The msec time seems the same for all sites too....
# TODO: Convert mydig_output to pdf
	return


	# rr = resp.additional[1]
	# print(rr.name)
	# print(rr.ttl)
	# print(dns.rdataclass.to_text(rr.rdclass))
	# print(dns.rdatatype.to_text(rr.rdtype))
	
	# time.time() for part 2 time testing
	#  matplotlib for part b

def main():
	resolve_request(str(sys.argv[1]))



if __name__ == "__main__":
	print("----------")
	main()
	print("----------")
