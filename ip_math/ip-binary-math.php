<?php

/**
* The not so short introduction to Subnetting in php
*
* Why not use long2ip ip2long
* 1 Because php stores all ints as signed on 32bit macines
* 2 They do not support ipv6 because longs cannot store ipv6
*
* Why use inet_ntop
* 1 because it handles all the things ipv6
* 2 DO NOT DUPLICATE CODE core function in 5.1.0+
* 3 is uses byte strings and they are perfect for math operation
*
* @php 5.1.0+
* @version 1
* @author Torben Egmose <torben@egmose.net>
* @link http://en.wikipedia.org/wiki/IPv4_subnetting_reference
*/
DEFINE('DEBUG', false);

/**
* Byte string representation of an IP
*
* Because life is to short for testing for valid byte strings that are IP's
* So we wrap a bytestring and we now know it is an IP when working with it
*
* @author Torben Egmose <torben@egmose.net>
* @license MIT
* @link http://php.net/manual/en/function.inet-ntop.php
* @php 5.1.0+
*
* @property-read mixed $value bytestring
*/
class binaryip
{
    /**
    * Bytestring
    * @var mixed
    */
    private $value;

    /**
    * Getters
    *
    * PHP does not have getters put we can emulate it
    *
    * @param mixed $key
    */
    public function __get($key)
    {
        switch($key)
        {
            case 'value':
                return $this->value;
            break;
        }
    }

    /**
    * Make new binary ip representation
    *
    * @param mixed $value IPv4 or IPv6
    */
    private function __construct($value)
    {
        $this->value = $value;
    }

    /**
    * Create bytestring from CIDR
    *
    * FILTER_FLAG_IPV* because thir is allready a representation
    * Well this should test for valid cidr and stuff if this was a libary. But it is not.
    *
    * @param mixed $type FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6
    * @param mixed $cidr
    * @return binaryip
    */
    static function fromCidr($type,$cidr)
    {
        return new binaryip( pack('H*', base_convert(str_pad(str_repeat(1,$cidr), $type == FILTER_FLAG_IPV4 ? 32 : 128 ,0,STR_PAD_RIGHT), 2, 16)) );
    }

    /**
    * Create bytestring from IP
    *
    * We just get that from the core function
    *
    * @param mixed $ip IPv6 or IPv4
    * @return binaryip
    */
    static function fromIP($ip)
    {
        return new binaryip(inet_pton($ip));
    }

    /**
    * Do OR function on bytestring
    *
    * @param binaryip $ip1
    * @param binaryip $ip2
    * @return binaryip
    */
    static function math_or(binaryip $ip1,binaryip $ip2)
    {
        return self::math_operation($ip1,$ip2,function($a,$b){ return $a | $b; });
    }

    /**
    * Do AND function on bytestring
    *
    * @param binaryip $ip1
    * @param binaryip $ip2
    * @return binaryip
    */
    static function math_and(binaryip $ip1,binaryip $ip2)
    {
        return self::math_operation($ip1,$ip2,function($a,$b){ return $a & $b; });
    }

    /**
    * Do NOT function on bytestring
    *
    * @param binaryip $ip
    * @return binaryip
    */
    static function math_not($ip)
    {
        return self::math_operation($ip, $ip,function($a,$b){ return ~ $a; });
    }

    /**
    * Do callable operation on every byte
    *
    * @param binaryip $ip1
    * @param binaryip $ip2
    * @return binaryip
    */
    static function math_operation(binaryip $ip1,binaryip $ip2, $operation)
    {
        if(strlen($ip1->value)!=strlen($ip2->value))
        {
            throw new ErrorException("Incompatible types");
        }

        $result = "";
        for($i=0; $i<strlen($ip1->value); $i++)
        {
            $result.= $operation( $ip1->value[$i] , $ip2->value[$i] );
        }

        return new binaryip( $result );
    }

    /**
    * Increment bytestring
    *
    * Well I did not trust the ++ function core to do the carry correct
    *
    * @param binaryip $ip
    * @return binaryip
    */
    static function math_inc(binaryip $ip)
    {
        $result = str_split($ip->value);
        $result = array_reverse($result);

        $carry = 1;
        foreach($result as $key => $value)
        {
            $sum = ord($value) + $carry;
            if($sum > 255)
            {
                $carry = $sum - 255;
                $result[$key] = chr(0);
            }
            else
            {
                $carry = 0;
                $result[$key] = chr($sum);
            }
        }

        if($carry > 0)
        {
            throw new Exception("Overflow");
        }

        return new binaryip( implode('',array_reverse($result)) );

    }

    /**
    * Find common CIDR for two bytestrings
    *
    * I do not think their is a core function for this
    *
    * @param binaryip $ip1
    * @param binaryip $ip2
    */
    static function find_longest_match(binaryip $ip1,binaryip $ip2)
    {
        // Convert to string in binary human format ( 0 and 1 )
        $temp = unpack('H*',$ip1->value);
        $ip1 = str_pad( base_convert($temp[1], 16, 2), strlen($ip1->value)==4 ? 32 : 128, 0, STR_PAD_LEFT);

        $temp = unpack('H*',$ip2->value);
        $ip2 = str_pad( base_convert($temp[1], 16, 2), strlen($ip2->value)==4 ? 32 : 128, 0, STR_PAD_LEFT);

        // Find the logest match of simular bits
        $match = 0;
        while($match < strlen($ip1))
        {
            if($ip1[$match]!=$ip2[$match])
            {
                return $match;
            }
            $match++;
        }
        return $match;
    }

    /**
    * Debuggin is nice
    *
    */
    public function __toString()
    {
        return inet_ntop($this->value);
    }
}

/**
* Networks are great abstraction
*
* Their are lots of rules for networks and stuff.
* So I assume you can find this information on your own
*
* @author Torben Egmose <torben@egmose.net>
* @license MIT
*
* @property-read binaryip $ip
* @property-read mixed $cidr
* @property-read mixed $type
*/
class network
{
    /**
    * Bytestring representing the IP provided
    *
    * @var binaryip
    */
    private $ip;

    /**
    * CIDR
    *
    * @var mixed
    * @link http://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing
    */
    private $cidr;

    /**
    * Filter type of the IP
    *
    * @var mixed
    */
    private $type;

    /**
    * Getters
    *
    * PHP does not have getters put we can emulate it
    *
    * @param mixed $key
    */
    public function __get($key)
    {
        switch($key)
        {
            case 'ip':
                return $this->ip;
            break;

            case 'cidr':
                return $this->cidr;
            break;

            case 'type':
                return $this->type;
            break;
        }
    }

    /**
    * Make a new network
    *
    * This is not a lib so no validation I assume you know things
    *
    * @param mixed $ip IPv4 | IPv6
    * @param mixed $cidr int between 1-128, 32 is maximum available for IPv4
    */
    public function __construct($ip,$cidr)
    {
        $this->ip = binaryip::fromIP($ip);
        $this->cidr = $cidr;

        if(filter_var($ip,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4))
        {
            $this->type = FILTER_FLAG_IPV4;
        }
        elseif(filter_var($ip,FILTER_VALIDATE_IP,FILTER_FLAG_IPV6))
        {
            $this->type = FILTER_FLAG_IPV6;
        }
        else
        {
            throw new ErrorException("That not an IP go away");
        }
    }

    /**
    * Network of the information provided
    *
    * @return binaryip
    */
    public function net()
    {
        return binaryip::math_and($this->ip, $this->netmask() );
    }

    /**
    * Netmask of the information provided
    *
    * @return binaryip
    */
    public function netmask()
    {
        return binaryip::fromCidr($this->type, $this->cidr);
    }

    /**
    * Wildcard of the information provided
    *
    * @return binaryip
    */
    public function wildcard()
    {
        return binaryip::math_not( $this->netmask() );
    }

    /**
    * Broadcast of the information provided
    *
    * @return binaryip
    */
    public function broadcast()
    {
        return binaryip::math_or( $this->net(), $this->wildcard() );
    }

    /**
    * Check if networks are in sequence without gab
    *
    * @param network $net1
    * @param network $net2
    * @return mixed
    */
    static function next_to_each_other(network $net1,network $net2)
    {
        $ip1_up = binaryip::math_inc($net1->broadcast());
        $ip2_up = binaryip::math_inc($net2->broadcast());

        return $net2->net()->value == $ip1_up->value || $net1->net()->value == $ip2_up->value;
    }

    /**
    * Debugging is nice
    *
    */
    public function __toString()
    {
        return $this->ip ."/". $this->cidr."\n";
    }
}

/**
* Supernets are an abstraction
*
* We need to return supernets and effected networks
* So enter supernet class
*
* @author Torben Egmose <torben@egmose.net>
* @license MIT
*
* @property-read network $SuperNet new supernet covering the same ip's as effected networks
* @property-read network[] $Affacted list of effected networks
*/
class supernet
{
    /**
    * Network representing the new super net
    *
    * @var network
    */
    private $SuperNet;

    /**
    * List of effetced networks
    *
    * @var network[]
    */
    private $Affacted;

    /**
    * Getters
    *
    * PHP does not have getters put we can emulate it
    *
    * @param mixed $key
    */
    public function __get($key)
    {
        switch($key)
        {
            case 'SuperNet':
                return $this->SuperNet;
            break;

            case 'Affacted':
                return $this->Affacted;
            break;
        }
    }

    /**
    * Make me an supernet
    *
    * @param mixed $SuperNet
    * @param mixed $Affacted
    */
    public function __construct($SuperNet,$Affacted)
    {
        $this->SuperNet = $SuperNet;
        $this->Affacted = $Affacted;
    }

    /**
    * Debugging is great
    *
    */
    public function __toString()
    {
        return "Super net:".$this->SuperNet.implode("",$this->Affacted)."\n";
    }
}

/**
* Networks representation
*
* We need networks to keep an ordered list of networks.
* Too keep assuptions clean and not have a huge amount of tests
*
* @author Torben Egmose <torben@egmose.net>
* @license MIT
*/
class networks
{
    /**
    * Network we should bundle
    *
    * @var network[]
    */
    public $nets = array();

    /**
    * Add network to bundle
    *
    * @param network $net
    */
    public function add(network $net)
    {
        $key = $net->net()->value;
        if(isset($this->nets[$key]))
        {
            throw new Exception("Duplicate net");
        }
        $this->nets[$key]=$net;
        ksort($this->nets);
    }

    /**
    * Calculate available super nets
    *
    * @return supernet[]
    */
    public function supernet()
    {
        if(count($this->nets)==0)
        {
            return null;
        }

        $out = array();
        $candidate = null;
        $matched = array();
        $last = null;

        reset($this->nets);
        while(true)
        {
            $net = current($this->nets);

            if(!is_null($candidate))
            {
                // Well we are in a loop so $net is different from candidate
                if(is_a($net,'network') && network::next_to_each_other($last, $net))
                {
                    // This worked so lets keep the candidate and update matched
                    $matched[] = $net;
                    $last = $net;
                }
                else
                {
                    // Did our candidate match any
                    if(count($matched)>0)
                    {
                        // So now we need to do some math

                        // So lets calculate the CIDR
                        // We know we do not have duplicates
                        // We know the first one is not ord
                        // We know they are in order

                        // Now comes the hard part we need to make super nets
                        // Yes nets as in multiple because CIDR might get to big and overflow

                        while(true)
                        {
                            $net = array_pop($matched);

                            $cidr = binaryip::find_longest_match( $net->net(), $candidate->net() );
                            $new_super_net = new network($candidate->ip, $cidr);

                            // Did we win the lotery?
                            if($new_super_net->broadcast()->value == $net->broadcast()->value)
                            {
                                // YAY the new super net is fine all is good

                                array_push($matched,$net);
                                array_unshift($matched,$candidate);

                                $out[] = new supernet($new_super_net, $matched);
                                break;
                            }
                            else
                            {
                                // Well we cannot use the last match
                                // We reset the pointer in the array and have it retest as candidate

                                $count = 0;
                                reset($this->nets);
                                while(current($this->nets) != $net)
                                {
                                    next($this->nets); // cycle pointer until we get their
                                }
                            }
                        }

                        $matched = array();
                        $candidate = null;
                        $last = null;
                    }
                    $candidate = null;
                }
            }

            $net = current($this->nets);

            if(!is_a($net,'network'))
            {
                break;
            }

            if(is_null($candidate))
            {
                $test = new network($net->ip,$net->cidr - 1);

                // is this network on an odd number and would creep up the scope
                if($net->net()->value == $test->net()->value)
                {
                    // No scope creep... ok lets select this one and continue
                    // So we select this as our first supernet candidate
                    $candidate = $net;
                    $last = $net;
                }
            }

            next($this->nets);
        }

        return $out;
    }
}

if(DEBUG)
{
    /**
    * Testing things is good
    *
    * @internal DO NOT USE ME IN PRODUCTION
    * @author Torben Egmose <torben@egmose.net>
    * @license MIT
    */
    class test
    {
        private $tests;
        private $count=0;

        public function __construct()
        {
        }

        public function add($key,network $net)
        {
            $this->tests[$key] = $net;
        }

        public function test($keys)
        {
            printf("\n\nTest no: %s\n",++$this->count);

            $work = new networks();
            foreach($keys as $key)
            {
                printf("Testing with %s %s",$key,$this->tests[$key]);
                $work->add($this->tests[$key]);
            }
            foreach($work->supernet() as $supernet)
            {
                print $supernet;
            }
        }
    }

    print "<pre>";
    $test = new test();
    $test->add('a',new network('10.0.0.2',24));
    $test->add('b',new network('10.0.1.2',24));
    $test->add('c',new network('10.0.2.2',24));
    $test->add('d',new network('10.0.3.2',24));
    $test->add('e',new network('10.0.4.2',24));
    $test->add('f',new network('10.0.5.2',24));

    // test that it works
    $test->test(array(
        'a',
        'b',
        'c',
        'd'
    ));

    // test that we can find a super net not connected to the first candidate
    $test->test(array(
        'a',
        //'b',
        'c',
        'd'
    ));

    // test that we can find the first supernet and remove a connected one not covered
    $test->test(array(
        'a',
        'b',
        //'c',
        'd'
    ));

    // test that it discards the first odd condidate
    $test->test(array(
        //'a',
        'b',
        'c',
        'd'
    ));


    // Test the that the candidate is released
    $test->test(array(
        'a',
        'b',
        'c',
        'd',
        'e',
    ));

    // Test it finds two supernets even if they all are touching
    $test->test(array(
        'a',
        'b',
        'c',
        'd',
        'e',
        'f',
    ));
}
