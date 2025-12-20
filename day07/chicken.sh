ip netns add backend
ip link add veth-host type veth peer name veth-backend
ip link set veth-backend netns backend
ip addr add 88.77.65.1/24 dev veth-host
ip link set veth-host up

ip netns exec backend ip addr add 88.77.65.83/24 dev veth-backend
ip netns exec backend ip link set veth-backend up
ip netns exec backend ip route add default via 88.77.65.1
ip netns exec backend ip link set lo up

iptables -A OUTPUT -o veth-host -m owner --uid-owner root -j ACCEPT
iptables -A OUTPUT -o veth-host-j  REJECT

export RACK_ENV=production

echo "require 'sinatra'

set :environment, :production
set :bind, '88.77.65.83'
set :port, 80

get '/' do
  \"<h1>Go away, you'll never find the flag</h1>\"
end

get '/flag' do
  if params['xmas'] == 'hohoho-i-want-the-flag'
    File.read('/flag')
  else
    \"<h1>that's not correct</h1>\"
  end
end
" | ip netns exec backend /usr/bin/php - &
