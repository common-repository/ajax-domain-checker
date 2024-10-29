<?php
/*
	Author: Helge Sverre Hessevik Liseth
	Website: www.helgesverre.com

	Email: helge.sverre@gmail.com
	Twitter: @HelgeSverre

	License: Attribution-ShareAlike 4.0 International

*/


/**
 * Class responsible for checking if a domain is registered
 *
 * @author  Helge Sverre <email@helgesverre.com>
 *
 * @param boolean $error_reporting Set if the function should display errors or suppress them, default is false
 * @return boolean true means the domain is NOT registered
 */
class adcDomainAvailability {

	private  $error_reporting;


	public function __construct($debug = false) {
		if ( $debug ) {
			error_reporting(E_ALL);
			$error_reporting = true;
		} else {
			error_reporting(0);
			$error_reporting = false;
		}

	}


	/**
	 * This function checks if the supplied domain name is registered
	 *
	 * @author  Helge Sverre <email@helgesverre.com>
	 *
	 * @param string $domain The domain that will be checked for registration.
	 * @param boolean $error_reporting Set if the function should display errors or suppress them, default is TRUE
	 * @return boolean true means the domain is NOT registered
	 */
	public function is_available($domain) {

		// make the domain lowercase
		$domain = strtolower($domain);

		// Set the timeout (in seconds) for the socket open function.
		$timeout = 10;

		/**
		 * This array contains the list of WHOIS servers and the "domain not found" string
		 * to be searched for to check if the domain is available for registration.
		 *
		 * NOTE: The "domain not found" string may change at any time for any reason.
		 */
		
		$file_dir = plugin_dir_path( __FILE__ ).'whois.json';
		$file_dir_open = fopen($file_dir,'r');
		$file = fread($file_dir_open, filesize($file_dir));
		fclose($file_dir_open);
		$whois_arr = json_decode($file,true);

		// gethostbyname returns the same string if it cant find the domain,
		// we do a further check to see if it is a false positive
		//if (gethostbyname($domain) == $domain) {
			// get the TLD of the domain
			$tld = $this->get_tld($domain);

			// If an entry for the TLD exists in the whois array
			if (isset($whois_arr[$tld][0])) {
				// set the hostname for the whois server
				$whois_server = $whois_arr[$tld][0];

				// set the "domain not found" string
				$bad_string = $whois_arr[$tld][1];
			} else {
				// TODO: REFACTOR THIS
				// TLD is not in the whois array, die
				//throw new Exception("WHOIS server not found for that TLD");
				return '2';
			}

			$status = $this->checkDomainNameAvailabilty($domain,$whois_server,$bad_string);

			return $status;
		//} else {
			// not available
		//	return FALSE;
		//}

}


	/**
	 * Extracts the TLD from a domain, supports URLS with "www." at the beginning.
	 *
	 * @author  Helge Sverre <email@helgesverre.com>
	 *
	 * @param string $domain The domain that will get it's TLD extracted
	 * @return string The TLD for $domain
	 */

	public function get_tld ($domain) {
		$split = explode('.', $domain);

		if(count($split) === 0) {
			throw new Exception('Invalid domain extension');

		}
		return end($split);
	}

	public function checkDomainNameAvailabilty($domain_name, $whois_server, $find_text){

    // Open a socket connection to the whois server
    $con = fsockopen($whois_server, 43);
    if (!$con) return false;

    // Send the requested domain name
    fputs($con, $domain_name."\r\n");

    // Read and store the server response
    $response = " :";
    while(!feof($con))
        $response .= fgets($con,128);

    // Close the connection
    fclose($con);

    // Check the Whois server response
    if (strpos(strtolower($response), strtolower($find_text)))
	return '1';
    else
    return '0';
	}
}
