<?php
/*
	Plugin Name: Ajax Domain Checker
	Plugin URI: http://asdqwe.net/
	Description: Check domain name availability for all Top Level Domains using shortcode or widget with Ajax search.
	Author: Asdqwe Dev
	Version: 1.3.0
	Author URI: http://asdqwe.net/plugins/wp-domain-checker/
	Text Domain: adc
 */


function adc_load_styles() {
	wp_register_style( 'adc-styles', plugins_url( 'assets/css/style.css', __FILE__ ) );
	wp_register_style( 'adc-styles-extras', plugins_url( 'assets/css/bootstrap-flat-extras.css', __FILE__ ) );
	wp_register_style( 'adc-styles-flat', plugins_url( 'assets/css/bootstrap-flat.css', __FILE__ ) );
	wp_register_script( 'adc-script', plugins_url( 'assets/js/script.js', __FILE__ ), array('jquery'));
 	wp_localize_script( 'adc-script', 'adc_ajax', array(
        'ajaxurl'       => admin_url( 'admin-ajax.php' ),
        'adc_nonce'     => wp_create_nonce( 'adc_nonce' ))
    );

}
add_action( 'wp_enqueue_scripts', 'adc_load_styles' );
add_action( 'admin_enqueue_scripts', 'adc_load_styles' );
function adc_load_styles_admin($hook) {
        // Load only on ?page=mypluginname
        if($hook != 'toplevel_page_ajax-domain-checker') {
                return;
        }
				wp_enqueue_style( 'adc-styles' );
				wp_enqueue_style( 'adc-styles-extras' );
				wp_enqueue_style( 'adc-styles-flat' );

}
add_action( 'admin_enqueue_scripts', 'adc_load_styles_admin' );
function adcMenu() {

	//create new top-level menu
	$page = add_menu_page('Ajax Domain Checker', 'Ajax Domain Checker', 'administrator', 'ajax-domain-checker', 'adc_menu_option' );
}

add_action('admin_menu', 'adcMenu');

function adc_menu_option() {
?>
<style>
#wdc-style ul li .glyphicon {
color:#3273dc;
padding-right:10px;
}
</style>
<div class="wrap about-wrap" style="padding:20px;background:#fff">
	<div id="wdc-style">
	<div class="row">
  <div class="col-md-6">
    <div class="boxed-content">
		<h2 class="about-title"><strong>WP Domain Checker</strong></h2>

<ul>
<li><i class="glyphicon glyphicon-ok"></i> Check domain name availability for any gTLD and ccTLD</li>
<li><i class="glyphicon glyphicon-ok"></i> Whois domain name</li>
<li><i class="glyphicon glyphicon-ok"></i> Made with AJAX</li>
<li><i class="glyphicon glyphicon-ok"></i> Easily use multiple checker with Shortcode</li>
<li><i class="glyphicon glyphicon-ok"></i> Easily use with Widget</li>
<li><i class="glyphicon glyphicon-ok"></i> Easily check from dashboard admin</li>
<li><i class="glyphicon glyphicon-ok"></i> Easily customize from admin panel</li>
<li><i class="glyphicon glyphicon-ok"></i> No need domain reseller API</li>
<li><i class="glyphicon glyphicon-ok"></i> Custom Link for Affiliates</li>
<li><i class="glyphicon glyphicon-ok"></i> Integrated with <strong>WHMCS</strong></li>
<li><i class="glyphicon glyphicon-ok"></i> Integrated with <strong>WooCommerce</strong></li>
<li><i class="glyphicon glyphicon-ok"></i> Support IDN Domain Check</li>
<li><i class="glyphicon glyphicon-ok"></i> Protected with New Google reCAPTCHA</li>
<li><i class="glyphicon glyphicon-ok"></i> Support more than <strong>1000 TLDs</strong></li>
<li><i class="glyphicon glyphicon-ok"></i> Allow Only Specific TLD Extensions to Check</li>
<li><i class="glyphicon glyphicon-ok"></i> Custom Pricing for WooCommerce</li>
<li><i class="glyphicon glyphicon-ok"></i> Custom CSS</li>
<li><i class="glyphicon glyphicon-ok"></i> Unlimited Colors</li>
<li><i class="glyphicon glyphicon-ok"></i> Multiple TLDs Check</li>
<li><i class="glyphicon glyphicon-ok"></i> Domain Caches</li>
<li><i class="glyphicon glyphicon-ok"></i> Custom Whois Server</li>
<li><i class="glyphicon glyphicon-ok"></i> Support WHMCS Bridge & WHMPRESS</li>
<li><i class="glyphicon glyphicon-ok"></i> Transfer Button</li>
<li><i class="glyphicon glyphicon-ok"></i> Whois Domain Lookup Only</li>
<li><i class="glyphicon glyphicon-ok"></i> Whois IP Address Lookup</li>
</ul>
<p><a href="https://1.envato.market/wdc" target="_blank"><button type="submit" id="Submit" class="btn btn-default btn-info">BUY PRO VERSION <i class="glyphicon glyphicon-star"></i> </button></a>
<a href="https://asdqwe.net/wordpress-plugins/wp-domain-checker-demo/" target="_blank"><button type="submit" id="Submit" class="btn btn-default btn-warning">PRO DEMO </button></a>
		</p>
	</div>
</div>
<div class="col-md-6">

	<div class="col screenshot-image">
		<a href="https://1.envato.market/wdc" target="_blank"><img src="https://asdqwe.net/wp-content/uploads/2020/07/wdc-preview.jpg"></a>
		<br><br><a href="https://1.envato.market/wdc" target="_blank"><img src="https://asdqwe.net/wp-content/uploads/2018/08/banner3.png"></a>
	</div>
</div>
</div>
</div>
</div>
<?php
}


function adc_display_func(){
	check_ajax_referer( 'adc_nonce', 'security' );

if(isset($_POST['domain']))
{
	$domain = str_replace(array('www.', 'http://'), NULL, $_POST['domain']);
	$split = explode('.', $domain);

		if(count($split) == 1) {
			$domain = $domain.".com";
		}
	$domain = preg_replace("/[^-a-zA-Z0-9.]+/", "", $domain);
	if(strlen($domain) > 0)
	{

		include ('DomainAvailability.php');
		$Domains = new adcDomainAvailability();
		$available = $Domains->is_available($domain);
		$custom_found_result_text = __('Congratulations! <b>'.$domain.'</b> is available!', 'adc');
    	$custom_not_found_result_text = __('Sorry! <b>'.$domain.'</b> is already taken!', 'adc');

		if ($available == '1') {
				$result = array('status'=>1,'domain'=>$domain, 'text'=> '<div class="callout callout-success alert-success clearfix available">
											<div class="col-xs-10" style="padding-left:1px;text-align:left;">
											<i class="glyphicon glyphicon-ok" style="margin-right:1px;"></i> '.__($custom_found_result_text,'adc').' </div>
											</div>
											');
		    	echo json_encode($result);
		} elseif ($available == '0') {
				$result = array('status'=>0,'domain'=>$domain, 'text'=> '<div class="callout callout-danger alert-danger clearfix not-available">
											<div class="col-xs-10" style="padding-left:1px;text-align:left;">
											<i class="glyphicon glyphicon-remove" style="margin-right:1px;"></i> '.__($custom_not_found_result_text, 'adc').'
											</div>
											</div>');
		    	echo json_encode($result);
		}elseif ($available == '2'){
				$result = array('status'=>0,'domain'=>$domain, 'text'=> '<div class="callout callout-warning alert-warning clearfix notfound">
											<div class="col-xs-10" style="padding-left:1px;text-align:left;">
											<i class="glyphicon glyphicon-exclamation-sign" style="margin-right:1px;"></i> '.__('WHOIS server not found for that TLD','adc').'
											</div>
											</div>');
		    	echo json_encode($result);
		}

	}
	else
	{
		echo 'Please enter the domain name';
	}
}
die();
}

add_action('wp_ajax_adc_display','adc_display_func');
add_action('wp_ajax_nopriv_adc_display','adc_display_func');

function adc_display_dashboard(){
	do_shortcode('[ajaxdomainchecker width="350"]');
}

function adc_add_dashboard_widgets() {

	wp_add_dashboard_widget(
                 'adc_dashboard_widget',
                 'Ajax Domain Checker',
                 'adc_display_dashboard'

        );
}
add_action( 'wp_dashboard_setup', 'adc_add_dashboard_widgets' );


function adc_display_shortcode($atts){
	wp_enqueue_style( 'adc-styles' );
	wp_enqueue_style( 'adc-styles-extras' );
	wp_enqueue_style( 'adc-styles-flat' );
	wp_enqueue_script( 'adc-script' );
		$image = plugins_url( 'assets/img/load.gif', __FILE__ );

		$atts = shortcode_atts(
		array(
			'width' => '600',
			'button' => 'Check'
		), $atts );

$content = "<div id='domain-form'>
	<div id='wdc-style' >
		<form method='post' action='./' id='form' class='pure-form'>

			<div class='input-group small' style='max-width:{$atts["width"]}px;'>
     			<input type='text' class='form-control' autocomplete='off' id='Search' name='domain' >
      				<span class='input-group-btn'>
					<button type='submit' id='Submit' class='btn btn-default btn-info'>{$atts["button"]}</button>
     	 			</span>
    		</div>
		<div id='loading'><img src='$image'></img></div>
	</form>
<div style='max-width:{$atts["width"]}px;'>
		<div id='results' class='result small'></div>
</div>
	</div>
</div>";

return $content;

}


add_shortcode( 'ajaxdomainchecker', 'adc_display_shortcode' );


class adc_widget extends WP_Widget {
	function __construct() {
		parent::__construct(false, $name = __('Ajax Domain Checker Widget'));
	}
	function form($instance) {
			if (isset($instance['title'])) {
				$title = $instance['title'];
				$width = $instance['width'];
				$button = $instance['button'];
			}else{
			$title = "Domain Availability Check";
			}
	?>
		<p>
			<label for="<?php echo $this->get_field_id('title'); ?>"><?php _e('Title:','adc'); ?>
				<input class="widefat" id="<?php echo $this->get_field_id('title'); ?>" name="<?php echo $this->get_field_name('title'); ?>" type="text" value="<?php echo $title; ?>" />
			</label>
		</p>
		<p>
		<label for="<?php echo $this->get_field_id('width'); ?>"><?php _e('Width:','adc'); ?>
			<input class="widefat" id="<?php echo $this->get_field_id('width'); ?>" name="<?php echo $this->get_field_name('width'); ?>" type="text" value="<?php echo $width; ?>" />
		</label>
		</p>
		<p>
		<label for="<?php echo $this->get_field_id('button'); ?>"><?php _e('Button Name:','adc'); ?>
			<input class="widefat" id="<?php echo $this->get_field_id('button'); ?>" name="<?php echo $this->get_field_name('button'); ?>" type="text" value="<?php echo $button; ?>" />
		</label>
		</p>
	<?php
	}
	function update($new_instance, $old_instance) {
	    $instance = array();
		$instance['title'] = ( ! empty( $new_instance['title'] ) ) ? strip_tags( $new_instance['title'] ) : '';
		$instance['width'] = ( ! empty( $new_instance['width'] ) ) ? strip_tags( $new_instance['width'] ) : '';
		$instance['button'] = ( ! empty( $new_instance['button'] ) ) ? strip_tags( $new_instance['button'] ) : '';

		return $instance;
	}

	function widget($args, $instance) {
		$title = $instance['title']; if ($title == '') $title = 'Domain Availability Check';
		$width = $instance['width']; if ($width == '') $width = '150';
		$button = $instance['button']; if ($button == '') $button = 'Check';
		echo $args['before_widget'];

	 	if ( $title ) {
	      echo $args['before_title'] . $title. $args['after_title'];
	   	}

		echo do_shortcode("[ajaxdomainchecker width='$width' button='$button']");

	  	echo $args['after_widget'];
		}
}

function register_adc_widget()
{
    register_widget( 'adc_widget' );
}
add_action( 'widgets_init', 'register_adc_widget');
