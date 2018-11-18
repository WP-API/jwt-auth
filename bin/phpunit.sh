#!/bin/bash
# Usage: ./tests/bin.sh xdebug_on /srv/www/wordpress-default/public_html/wp-content/plugins/jwt-auth
# Runs the PHPUnit tests with html coverage output in the VVV wordpress-default site.

set -e

xdebug=$1
if [ -z "$xdebug" ]; then
	xdebug="xdebug_off"
fi

path=$2
if [ -z "$path" ]; then
	path="/srv/www/wordpress-default/public_html/wp-content/plugins/jwt-auth"
fi

if [ $xdebug = "xdebug_on" ]; then
    COVERAGE="--coverage-html $path/coverage";
fi

vagrant ssh -c "$xdebug && cd $path && WP_TESTS_DIR=tests/wp-tests/phpunit phpunit $COVERAGE"
