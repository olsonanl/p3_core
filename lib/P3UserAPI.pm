package P3UserAPI;

# This is a SAS Component

# Updated for new PATRIC.

use File::Temp qw(:seekable);
use LWP::UserAgent;
use strict;
use POSIX qw(strftime);
use JSON::XS;
use URI::Escape;
use Digest::MD5 'md5_hex';
use Time::HiRes 'gettimeofday';
use HTTP::Request::Common;
use Data::Dumper;
use P3ClientUA;

our $have_p3auth;
eval {
    require P3AuthToken;
    $have_p3auth = 1;
};

no warnings 'once';

eval { require FIG_Config; };

our $default_url = $FIG_Config::p3_user_api_url
    || "https://user.patricbrc.org";

our $token_path;
if ($^O eq 'MSWin32')
{
    my $dir = $ENV{HOME} || $ENV{HOMEPATH};
    if (! $dir) {
        require FIG_Config;
        $dir = $FIG_Config::userHome;
    }
    $token_path = "$dir/.patric_token";
} else {
    $token_path = "$ENV{HOME}/.patric_token";
}

our %EncodeMap = ('<' => '%60', '=' => '%61', '>' => '%62', '"' => '%34', '#' => '%35', '%' => '%37',
                  '+' => '%43', '/' => '%47', ':' => '%3A', '{' => '%7B', '|' => '%7C', '}' => '%7D',
                  '^' => '%94', '`' => '%96', '&' => '%26', "'" => '%27');

use warnings 'once';

use base 'Class::Accessor';
__PACKAGE__->mk_accessors(qw(url ua
                            ));

sub new {
    my ( $class, $url, $token, $params ) = @_;

    if ($token)
    {
        if (ref($token) eq 'P3AuthToken')
        {
            $token = $token->token();
        }
    }
    else
    {
        if ($have_p3auth)
        {
            my $token_obj = P3AuthToken->new();
            if ($token_obj)
            {
                $token = $token_obj->token;
            }
        }
        else
        {
            if (open(my $fh, "<", $token_path))
            {
                $token = <$fh>;
                chomp $token;
                close($fh);
            }
        }
    }

    $url ||= $default_url;
    my $self = {
        url        => $url,
        chunk_size => 25000,
        ua         => P3ClientUA::new_ua(),
        token      => $token,
        benchmark  => 0,
        raw        => 0,
        (ref($params) eq 'HASH' ? %$params : ()),
    };

    return bless $self, $class;
}

sub auth_header {
    my ($self) = @_;
    if ( $self->{token} ) {
        return ( "Authorization", $self->{token} );
    } else {
        return ();
    }
}

sub get_current_user
{
    my($self) = @_;
    if ($self->{token})
    {
    my $t = P3AuthToken->new(token => $self->{token});
    my $u = $t->user_id;
    $u =~ s/\@.*$//;
    return $self->get_user($u);
    }
    return undef;
}

sub get_user
{
    my($self, $user) = @_;

    my $res = $self->ua->get($self->url . "/user/$user",
                 $self->auth_header);

    if (!$res->is_success)
    {
    die "user retrieve failed with " . $res->code . " " . $res->status_line . " " . $res->content;
    }
    my $dat = $res->content;
    my $u = eval { decode_json($dat); };
    if ($@)
    {
    die "Error parsing result: $@";
    }
    return $u;
}


#
# I shoved this down here because the regexp makes autoindenter puke.
#
sub url_encode
{
    my($self, $q) = @_;
    $q =~ s/([<>"#\%+\/{}\|\\\^\[\]:`'])/$EncodeMap{$1}/gs;
    return $q;
}


1;
